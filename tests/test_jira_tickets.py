"""Jira Cloud tasks for qualifying findings (app.ticketing).

Jira is always a fake here (FakeJira.fetch) - no test talks to a real Jira site, so these
tests prove the logic, not connectivity to example.atlassian.net.
"""
import base64
import json
import logging
import urllib.parse
from datetime import timedelta

import pytest
from correlation_data import FakeNvd, add_version_scan, session
from sqlalchemy import func, select, update

from app import config
from app.audit.models import AuditEvent
from app.correlation import engine
from app.correlation.models import Finding, FindingStatus
from app.database import session_scope, utcnow
from app.ticketing import jira as jira_mod
from app.ticketing import service
from app.ticketing.models import JiraTicket
from app.ticketing.policy import Policy, classification, qualifies

IP = "10.0.0.5"
TOKEN = "tok-SECRET-do-not-log-123"
BASE = "https://example.atlassian.net"
PRIORITIES = ["Highest", "High", "Medium", "Low", "Lowest"]


class FakeJira:
    """Jira Cloud stand-in. `fail[op]` holds scripted outcomes for the next calls of an operation
    (meta / create / search / comment / status): an exception to raise, an int HTTP status, a
    (status, headers, body) tuple, or "ambiguous" (create the issue, then lose the answer)."""

    def __init__(self):
        self.issues: dict[str, dict] = {}
        self.calls: list[tuple[str, str, dict, bytes | None, float]] = []
        self.comments: dict[str, list[dict]] = {}
        self.fail: dict[str, list] = {}
        self.issue_types = [{"id": "10003", "name": "Task"}, {"id": "10001", "name": "Epic"}]
        self.create_fields = ["summary", "issuetype", "project", "description", "labels", "priority", "assignee"]

    @staticmethod
    def _op(method, path):
        if path.startswith("/rest/api/3/issue/createmeta/"):
            return "meta"
        if method == "POST" and path == "/rest/api/3/issue":
            return "create"
        if path.startswith("/rest/api/3/search/jql"):
            return "search"
        if path.endswith("/comment"):
            return "comment"
        return "status"

    def _create(self, body):
        key = f"ASSET-{len(self.issues) + 1}"
        self.issues[key] = json.loads(body)["fields"]
        return key

    def _meta(self, path):
        if not path.startswith("/rest/api/3/issue/createmeta/ASSET/"):
            return 404, {}, b'{"errorMessages": ["No project could be found with key"]}'
        if "/issuetypes/" not in path:
            return 200, {}, json.dumps({"issueTypes": self.issue_types}).encode()
        fields = [{"fieldId": f, **({"allowedValues": [{"name": p} for p in PRIORITIES]} if f == "priority" else {})}
                  for f in self.create_fields]
        return 200, {}, json.dumps({"fields": fields}).encode()

    def fetch(self, method, url, headers, body, timeout):
        assert url.startswith(BASE + "/rest/api/3/"), url        # never anywhere else
        path = url[len(BASE):]
        self.calls.append((method, path, headers, body, timeout))
        op = self._op(method, path)
        scripted = self.fail.get(op)
        if scripted:
            action = scripted.pop(0)
            if isinstance(action, Exception):
                raise action
            if action == "ambiguous":
                self._create(body)
                raise TimeoutError("timed out")
            if isinstance(action, int):
                return action, {}, json.dumps({"errorMessages": [f"scripted {action}"]}).encode()
            return action
        if op == "meta":
            return self._meta(path)
        if op == "create":
            return 201, {}, json.dumps({"id": "1", "key": self._create(body)}).encode()
        if op == "search":
            jql = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["jql"][0]
            label = jql.split('labels = "')[1].split('"')[0]
            found = [{"key": k} for k, f in self.issues.items() if label in f["labels"]]
            return 200, {}, json.dumps({"issues": found[:1]}).encode()
        if op == "comment":
            key = path.split("/issue/")[1].split("/")[0]
            self.comments.setdefault(key, []).append(json.loads(body)["body"])
            return 201, {}, b'{"id": "10"}'
        return 200, {}, json.dumps({"fields": {"status": {"name": "In Progress"}}}).encode()

    def ops(self, op):
        return [c for c in self.calls if self._op(c[0], c[1]) == op]


@pytest.fixture
def nvd():
    return FakeNvd()


@pytest.fixture
def fake_jira(monkeypatch):
    fake = FakeJira()
    monkeypatch.setattr(service, "client", lambda fetch=None: jira_mod.JiraClient(service.settings(), fake.fetch))
    return fake


@pytest.fixture
def jira_on(monkeypatch, fake_jira):
    for name, value in {"JIRA_ENABLED": True, "JIRA_BASE_URL": BASE, "JIRA_PROJECT_KEY": "ASSET",
                        "JIRA_EMAIL": "bot@cybermock.io", "JIRA_API_TOKEN": TOKEN, "JIRA_ISSUE_TYPE": "Task",
                        "JIRA_LABEL": "finding", "JIRA_AUTO_CREATE": True, "JIRA_MIN_SEVERITY": "HIGH",
                        "JIRA_INCLUDE_LOW_CONFIDENCE": False, "JIRA_MAX_RETRIES": 2, "JIRA_TIMEOUT_SECONDS": 10,
                        "PUBLIC_URL": "https://cag.cybermock.io"}.items():
        monkeypatch.setattr(config, name, value)
    return fake_jira


def critical_asset(make_asset, **kw):
    # vsftpd 2.3.4 backdoor (CVSS 9.8) on an internet-facing critical production asset -> 94 CRITICAL
    return make_asset(**{"name": "web-server-01", "ip_address": IP, "internet_facing": "yes",
                         "criticality": "critical", "environment": "production", **kw})


HIGH = {"internet_facing": "no", "criticality": "high"}                               # 77 HIGH
MEDIUM = {"internet_facing": "no", "criticality": "low", "environment": "development"}  # 61 MEDIUM


def correlate(nvd, ports=(21, "vsftpd", "2.3.4")):
    add_version_scan(IP, [ports])
    with session() as s:
        return engine.run_correlation(s, nvd)


def correlate_quietly(nvd, monkeypatch):
    """Correlate with the integration switched off (nothing queued), then switch it back on."""
    monkeypatch.setattr(config, "JIRA_ENABLED", False)
    correlate(nvd)
    monkeypatch.setattr(config, "JIRA_ENABLED", True)


def tickets():
    with session_scope() as db:
        return [(t.finding_id, t.state, t.issue_key, t.attempts, t.last_error, t.error_category)
                for t in db.scalars(select(JiraTicket).order_by(JiraTicket.id))]


def deliver(later=timedelta(0)):
    with session() as s:
        return service.deliver_due(s, service.client(), now=utcnow() + later)


def audit_actions(prefix="jira."):
    with session_scope() as db:
        return [(e.action, e.outcome.value, e.details, e.actor_username) for e in
                db.scalars(select(AuditEvent).where(AuditEvent.action.startswith(prefix)).order_by(AuditEvent.id))]


def finding_row():
    with session_scope() as db:
        f = db.scalars(select(Finding)).unique().one()
        return f.id, f.status, f.ticket_key


# --- qualification -----------------------------------------------------------------------------

@pytest.mark.parametrize(("level", "policy", "expected"), [
    ("CRITICAL", Policy(), True),
    ("HIGH", Policy(), True),
    ("MEDIUM", Policy(), False),
    ("LOW", Policy(), False),
    ("HIGH", Policy(min_severity="CRITICAL"), False),
    ("MEDIUM", Policy(min_severity="MEDIUM"), True),
    ("CRITICAL", Policy(auto_create=False), False),
])
def test_qualification_by_risk_level(level, policy, expected):
    ok, reason = qualifies(policy, status="open", asset_active=True, level=level, confidence="high",
                           has_manual_ticket=False)
    assert ok is expected and reason


@pytest.mark.parametrize(("kw", "why"), [
    ({"status": "accepted_risk"}, "finding is accepted risk"),
    ({"status": "resolved"}, "finding is resolved"),
    ({"status": "verified_fixed"}, "finding is verified fixed"),
    ({"asset_active": False}, "asset is inactive"),
    ({"has_manual_ticket": True}, "a ticket is already linked"),
    ({"level": None}, "no risk assessment"),
])
def test_base_checks_apply_to_automatic_and_manual_tasks(kw, why):
    args = {"status": "open", "asset_active": True, "level": "CRITICAL", "confidence": "high",
            "has_manual_ticket": False, **kw}
    for manual in (False, True):
        ok, reason = qualifies(Policy(), manual=manual, **args)
        assert not ok and why in reason


def test_unconfirmed_findings_need_validation_or_opt_in():
    args = {"status": "open", "asset_active": True, "level": "CRITICAL", "confidence": "low",
            "has_manual_ticket": False}
    ok, reason = qualifies(Policy(), **args)
    assert not ok and "requires validation" in reason
    assert qualifies(Policy(include_low_confidence=True), **args)[0]
    assert qualifies(Policy(), manual=True, **args)[0]                    # an analyst may decide
    assert classification("open", "high") == "confirmed version match"
    assert classification("open", "low") == "potential - requires validation"
    assert classification("verified_fixed", "high") == "resolved"


def test_disabled_integration_queues_nothing_and_sends_nothing(client, make_asset, nvd, fake_jira):
    critical_asset(make_asset)
    assert config.JIRA_ENABLED is False                                   # off by default
    correlate(nvd)
    assert tickets() == [] and fake_jira.calls == []
    status = client.get("/integrations/jira").json()
    assert status["state"] == "disabled" and status["base_url"] is None
    finding_id = finding_row()[0]
    r = client.post(f"/findings/{finding_id}/ticket")
    assert r.status_code == 409 and "disabled" in r.json()["detail"]


def test_missing_configuration_fails_safely(client, make_asset, nvd, monkeypatch, fake_jira):
    monkeypatch.setattr(config, "JIRA_ENABLED", True)
    monkeypatch.setattr(config, "JIRA_BASE_URL", BASE)
    monkeypatch.setattr(config, "JIRA_PROJECT_KEY", "")
    monkeypatch.setattr(config, "JIRA_EMAIL", "bot@cybermock.io")
    monkeypatch.setattr(config, "JIRA_API_TOKEN", TOKEN)
    critical_asset(make_asset)
    run = correlate(nvd)
    assert run.status == "success" and tickets() == [] and fake_jira.calls == []   # assessment unaffected
    body = client.get("/integrations/jira").text
    assert json.loads(body)["state"] == "misconfigured" and "CAG_JIRA_PROJECT_KEY" in body
    assert TOKEN not in body


# --- creation and content ----------------------------------------------------------------------

def test_critical_finding_creates_one_task_with_label_project_type_and_evidence(client, make_asset, nvd, jira_on):
    asset = critical_asset(make_asset)
    run = correlate(nvd)
    assert run.status == "success"
    finding_id, status, ticket_key = finding_row()
    assert tickets() == [(finding_id, "created", "ASSET-1", 1, None, None)]
    assert (status, ticket_key) == (FindingStatus.OPEN, "ASSET-1")       # linked to the finding

    fields = jira_on.issues["ASSET-1"]
    assert fields["project"] == {"key": "ASSET"} and fields["issuetype"] == {"id": "10003"}   # Task
    assert "finding" in fields["labels"] and "cyberasset-guard" in fields["labels"]
    assert fields["priority"] == {"name": "Highest"}
    assert fields["summary"] == "[CRITICAL] CVE-2011-2523 in vsftpd 2.3.4 – web-server-01"
    text = json.dumps(fields["description"])
    for expected in ("Security Finding", f"{finding_id} (CyberAsset Guard)", "confirmed version match",
                     "94/100", "Detected At", "CVE-2011-2523", "Technical Evidence", "vsftpd 2.3.4 on tcp/21",
                     "network version scan #", "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
                     "Context and Risk Explanation", "production", "critical", IP,
                     "Recommended Remediation", "Verification Criteria",
                     f"https://cag.cybermock.io/#/assets/{asset['id']}"):
        assert expected in text, expected
    assert TOKEN not in text and "Requires validation" not in text

    created = [a for a in audit_actions() if a[0] == "jira.ticket_created"]
    assert len(created) == 1 and created[0][2]["issue_key"] == "ASSET-1" and created[0][3] == "system"
    item = client.get(f"/assets/{asset['id']}/findings").json()["items"][0]
    assert item["ticket"]["issue_url"] == f"{BASE}/browse/ASSET-1" and item["ticket"]["state"] == "created"
    assert jira_on.calls[0][4] == 10                                      # CAG_JIRA_TIMEOUT_SECONDS


def test_high_finding_qualifies_and_maps_to_high_priority(make_asset, nvd, jira_on):
    critical_asset(make_asset, **HIGH)
    correlate(nvd)
    fields = jira_on.issues["ASSET-1"]
    assert fields["summary"].startswith("[HIGH] ") and fields["priority"] == {"name": "High"}


def test_priority_is_omitted_when_the_project_does_not_offer_it(make_asset, nvd, jira_on):
    jira_on.create_fields.remove("priority")
    critical_asset(make_asset)
    correlate(nvd)
    assert "priority" not in jira_on.issues["ASSET-1"]


def test_medium_and_low_findings_get_no_automatic_task(client, make_asset, nvd, jira_on):
    asset = critical_asset(make_asset, **MEDIUM)
    correlate(nvd)
    assert tickets() == [] and jira_on.calls == []
    eligibility = client.get(f"/assets/{asset['id']}/findings").json()["items"][0]["jira_eligibility"]
    assert eligibility["automatic"] is False and eligibility["manual"] is True
    assert "below HIGH" in eligibility["reason"] and "analyst can still create" in eligibility["reason"]


def test_minimum_severity_is_configurable(make_asset, nvd, jira_on, monkeypatch):
    critical_asset(make_asset, **MEDIUM)
    monkeypatch.setattr(config, "JIRA_MIN_SEVERITY", "MEDIUM")
    correlate(nvd)
    assert jira_on.issues["ASSET-1"]["summary"].startswith("[MEDIUM] ")


def test_auto_create_off_means_manual_tasks_only(client_as, make_asset, nvd, jira_on, monkeypatch):
    critical_asset(make_asset)
    monkeypatch.setattr(config, "JIRA_AUTO_CREATE", False)
    correlate(nvd)
    assert tickets() == []
    assert client_as("analyst").post(f"/findings/{finding_row()[0]}/ticket").status_code == 202
    assert tickets()[0][1:3] == ("created", "ASSET-1")


def test_unconfirmed_finding_is_not_automatic_and_stays_unconfirmed_in_the_task(make_asset, nvd, jira_on,
                                                                               monkeypatch):
    critical_asset(make_asset)
    correlate_quietly(nvd, monkeypatch)
    with session_scope() as db:
        db.execute(update(Finding).values(confidence="low"))
    with session() as s:
        assert service.enqueue_qualifying(s) == 0
    monkeypatch.setattr(config, "JIRA_INCLUDE_LOW_CONFIDENCE", True)
    with session() as s:
        assert service.enqueue_qualifying(s) == 1
    deliver()
    text = json.dumps(jira_on.issues["ASSET-1"]["description"])
    assert "potential - requires validation" in text and "Requires validation" in text
    assert "confirmed version match" not in text


def test_untrusted_values_are_plain_text_in_the_description(make_asset, nvd, jira_on):
    critical_asset(make_asset, hostname="evil.cybermock.local", description="[link|https://evil] *bold*")
    correlate(nvd)
    links = [m["attrs"]["href"] for node in _walk(jira_on.issues["ASSET-1"]["description"])
             for m in node.get("marks", []) if m["type"] == "link"]
    assert all(h.startswith(("https://nvd.nist.gov/", "https://cag.cybermock.io/")) for h in links)


def _walk(node):
    yield node
    for child in node.get("content", []):
        yield from _walk(child)


# --- metadata / project / issue type -------------------------------------------------------------

def test_unknown_project_is_a_permanent_invalid_project_error(make_asset, nvd, jira_on, monkeypatch):
    monkeypatch.setattr(config, "JIRA_PROJECT_KEY", "NOPE")
    critical_asset(make_asset)
    correlate(nvd)
    (_, state, key, attempts, error, category) = tickets()[0]
    assert (state, key, category) == ("error", None, "invalid_project") and "HTTP 404" in error
    assert jira_on.ops("create") == []


def test_missing_task_issue_type_is_reported(make_asset, nvd, jira_on):
    jira_on.issue_types = [{"id": "10001", "name": "Epic"}]
    critical_asset(make_asset)
    correlate(nvd)
    (_, state, _, _, error, category) = tickets()[0]
    assert (state, category) == ("error", "invalid_project") and "'Task' is not available" in error


def test_missing_labels_field_is_reported(make_asset, nvd, jira_on):
    jira_on.create_fields.remove("labels")
    critical_asset(make_asset)
    correlate(nvd)
    assert tickets()[0][1] == "error" and "Labels field" in tickets()[0][4]


# --- idempotency ---------------------------------------------------------------------------------

def test_repeated_scans_reuse_the_task(make_asset, nvd, jira_on):
    critical_asset(make_asset)
    for _ in range(3):
        correlate(nvd)
        deliver()
    assert len(jira_on.ops("create")) == 1 and len(tickets()) == 1


def test_concurrent_processing_creates_one_task(make_asset, nvd, jira_on, monkeypatch):
    critical_asset(make_asset)
    correlate_quietly(nvd, monkeypatch)
    finding_id = finding_row()[0]
    with session() as a, session() as b:                # two workers / two assessment runs
        assert service._new_ticket(a, finding_id, "auto", None) is not None
        a.commit()
        assert service._new_ticket(b, finding_id, "auto", None) is None     # UNIQUE(finding_id)
        b.commit()
    now = utcnow()
    with session_scope() as db:
        ticket_id = db.scalar(select(JiraTicket.id))
    with session() as a, session() as b:
        assert [service._claim(a, ticket_id, now), service._claim(b, ticket_id, now)] == [True, False]
    deliver(later=service.LEASE + timedelta(seconds=1))  # the abandoned claim is recovered
    assert len(jira_on.ops("create")) == 1 and tickets()[0][1] == "created"


def test_temporary_failures_are_retried_with_backoff(make_asset, nvd, jira_on):
    critical_asset(make_asset)
    jira_on.fail["create"] = [503, (429, {"Retry-After": "900"}, b"")]
    correlate(nvd)                                       # attempt 1: 503 (outcome unknown)
    (_, state, key, attempts, error, category) = tickets()[0]
    assert (state, key, attempts, category) == ("failed", None, 1, "server") and "HTTP 503" in error
    assert deliver() == {}                               # not due yet (backoff)
    deliver(later=timedelta(minutes=2))                  # attempt 2: 429 with Retry-After 900 s
    with session_scope() as db:
        t = db.scalars(select(JiraTicket)).one()
        assert (t.state, t.error_category) == ("failed", "rate_limited")
        assert t.next_attempt_at - t.last_attempt_at >= timedelta(seconds=900)
    deliver(later=timedelta(minutes=20))                 # attempt 3 succeeds
    assert tickets()[0][1:4] == ("created", "ASSET-1", 3)
    assert finding_row()[1] == FindingStatus.OPEN        # the finding was never touched


@pytest.mark.parametrize(("failure", "category"), [
    (TimeoutError("slow"), "timeout"),
    (OSError("network unreachable"), "network"),
])
def test_network_problems_are_retried(make_asset, nvd, jira_on, failure, category):
    critical_asset(make_asset)
    jira_on.fail["search"] = [failure]
    correlate(nvd)
    assert tickets()[0][1] == "failed" and tickets()[0][5] == category
    deliver(later=timedelta(minutes=2))
    assert tickets()[0][1] == "created"


def test_ambiguous_timeout_never_creates_a_second_task(make_asset, nvd, jira_on):
    critical_asset(make_asset)
    jira_on.fail["create"] = ["ambiguous"]               # Jira creates the issue, the answer is lost
    correlate(nvd)
    assert tickets()[0][1] == "failed" and len(jira_on.issues) == 1
    deliver(later=timedelta(minutes=5))                  # retry: found by label -> adopted
    assert tickets()[0][1:3] == ("created", "ASSET-1") and len(jira_on.issues) == 1
    assert len(jira_on.ops("create")) == 1
    created = [a for a in audit_actions() if a[0] == "jira.ticket_created"][0]
    assert created[2]["adopted_existing_issue"] is True


def test_malformed_create_response_is_treated_as_ambiguous(make_asset, nvd, jira_on):
    critical_asset(make_asset)
    jira_on.fail["create"] = [(201, {}, b"<html>proxy</html>")]
    correlate(nvd)
    assert tickets()[0][1] == "failed" and tickets()[0][5] == "malformed"
    deliver(later=timedelta(minutes=5))
    assert tickets()[0][1] == "created"


def test_restart_recovers_a_task_left_in_sending(make_asset, nvd, jira_on, monkeypatch):
    critical_asset(make_asset)
    correlate_quietly(nvd, monkeypatch)
    with session() as s:
        service.enqueue_qualifying(s)
    with session_scope() as db:                          # a worker crashed mid-delivery
        db.execute(update(JiraTicket).values(state="sending", lease_until=utcnow() - timedelta(minutes=1)))
    deliver()
    assert tickets()[0][1] == "created" and len(jira_on.ops("create")) == 1


# --- permanent errors, bounded retries, manual retry, RBAC ----------------------------------------

@pytest.mark.parametrize(("http_status", "category"), [
    (400, "invalid_request"), (401, "authentication"), (403, "permission"),
])
def test_permanent_errors_stop_retrying_and_are_audited(make_asset, nvd, jira_on, http_status, category):
    critical_asset(make_asset)
    jira_on.fail["create"] = [http_status]
    correlate(nvd)
    (_, state, _, attempts, error, cat) = tickets()[0]
    assert (state, attempts, cat) == ("error", 1, category) and f"HTTP {http_status}" in error
    deliver(later=timedelta(days=1))
    assert len(jira_on.ops("create")) == 1               # never retried automatically
    failed = [a for a in audit_actions() if a[0] == "jira.ticket_failed"]
    assert failed and failed[0][1] == "failure" and failed[0][2]["category"] == category


def test_retries_are_bounded(make_asset, nvd, jira_on):
    critical_asset(make_asset)
    jira_on.fail["create"] = [500, 500, 500, 500]
    correlate(nvd)
    for hours in (1, 2, 3, 4):
        deliver(later=timedelta(hours=hours))
    assert tickets()[0][1:4] == ("error", None, 3)       # 1 attempt + CAG_JIRA_MAX_RETRIES = 2
    assert len(jira_on.ops("create")) == 3
    assert [a[2]["reason"] for a in audit_actions() if a[0] == "jira.ticket_failed"] == ["attempts exhausted"]


def test_analyst_retries_a_failed_task_and_viewer_cannot(client, client_as, make_asset, nvd, jira_on):
    critical_asset(make_asset)
    jira_on.fail["create"] = [401]
    correlate(nvd)
    finding_id = finding_row()[0]
    assert client_as("viewer").post(f"/findings/{finding_id}/ticket").status_code == 403
    r = client_as("analyst").post(f"/findings/{finding_id}/ticket")
    assert r.status_code == 202 and r.json()["queued"] is True
    assert client.get(f"/findings/{finding_id}/ticket").json()["issue_key"] == "ASSET-1"
    retry = [a for a in audit_actions() if a[0] == "jira.ticket_retry"]
    assert retry and retry[0][2]["previous_state"] == "error" and retry[0][3] == "analyst-user"
    again = client_as("analyst").post(f"/findings/{finding_id}/ticket").json()
    assert again["queued"] is False and again["ticket"]["issue_key"] == "ASSET-1"     # no duplicate
    assert len(jira_on.issues) == 1


def test_manual_task_below_the_threshold(client_as, make_asset, nvd, jira_on):
    critical_asset(make_asset, **MEDIUM)
    correlate(nvd)
    assert tickets() == []
    r = client_as("analyst").post(f"/findings/{finding_row()[0]}/ticket")
    assert r.status_code == 202
    assert tickets()[0][1:3] == ("created", "ASSET-1")
    assert jira_on.issues["ASSET-1"]["priority"] == {"name": "Medium"}
    actions = [(a[0], a[3]) for a in audit_actions()]
    assert actions == [("jira.ticket_requested", "analyst-user"), ("jira.ticket_created", "analyst-user")]


def test_manual_task_is_refused_for_an_ineligible_finding(client, client_as, make_asset, nvd, jira_on, monkeypatch):
    critical_asset(make_asset)
    correlate_quietly(nvd, monkeypatch)
    finding_id = finding_row()[0]
    client.patch(f"/findings/{finding_id}", json={"status": "accepted_risk", "reason": "compensating control"})
    r = client_as("analyst").post(f"/findings/{finding_id}/ticket")
    assert r.status_code == 409 and "accepted risk" in r.json()["detail"]
    assert tickets() == [] and jira_on.calls == []


def test_ticket_endpoints_require_login_and_permissions(anon_client, client_as, jira_on):
    assert anon_client.get("/integrations/jira").status_code == 401
    assert anon_client.get("/findings/1/ticket").status_code == 401
    assert client_as("viewer").post("/findings/1/ticket/sync").status_code == 403
    assert client_as("analyst").post("/findings/999/ticket").status_code == 404


def test_automatic_task_is_skipped_when_the_risk_was_accepted_meanwhile(client, make_asset, nvd, jira_on):
    critical_asset(make_asset)
    jira_on.fail["search"] = [503]
    correlate(nvd)
    finding_id = finding_row()[0]
    assert client.patch(f"/findings/{finding_id}", json={"status": "accepted_risk",
                                                          "reason": "compensating control"}).status_code == 200
    deliver(later=timedelta(minutes=5))
    assert tickets()[0][1] == "skipped" and jira_on.ops("create") == []


# --- lifecycle: verification and recurrence --------------------------------------------------------

def test_fixed_finding_is_verified_and_recurrence_reuses_the_task(make_asset, nvd, jira_on):
    critical_asset(make_asset)
    correlate(nvd)
    correlate(nvd, ports=(21, "vsftpd", "3.0.5"))        # re-scan: non-affected version
    assert finding_row()[1] == FindingStatus.VERIFIED_FIXED
    deliver()
    notes = json.dumps(jira_on.comments["ASSET-1"])
    assert "Verification" in notes and "verified fixed" in notes
    correlate(nvd)                                        # vulnerable again -> reopened, same task
    deliver()
    assert finding_row()[1] == FindingStatus.OPEN and len(jira_on.issues) == 1
    assert "reopened" in json.dumps(jira_on.comments["ASSET-1"][-1])


def test_sync_reads_the_jira_status_without_changing_the_finding(client, make_asset, nvd, jira_on):
    critical_asset(make_asset)
    correlate(nvd)
    finding_id = finding_row()[0]
    r = client.post(f"/findings/{finding_id}/ticket/sync")
    assert r.status_code == 200 and r.json()["jira_status"] == "In Progress"
    assert finding_row()[1] == FindingStatus.OPEN


def test_status_endpoint_counts_and_hides_credentials(client, make_asset, nvd, jira_on):
    critical_asset(make_asset)
    correlate(nvd)
    body = client.get("/integrations/jira").text
    data = json.loads(body)
    assert data["state"] == "enabled" and data["tickets"]["created"] == 1 and data["label"] == "finding"
    assert data["policy"]["levels"] == ["CRITICAL", "HIGH"] and data["policy"]["min_severity"] == "HIGH"
    assert TOKEN not in body and "bot@cybermock.io" not in body


# --- security ------------------------------------------------------------------------------------

def test_credentials_never_reach_logs_errors_api_or_audit(client, make_asset, nvd, jira_on, caplog):
    critical_asset(make_asset)
    basic = base64.b64encode(f"bot@cybermock.io:{TOKEN}".encode()).decode()
    jira_on.fail["create"] = [401]
    with caplog.at_level(logging.DEBUG):
        correlate(nvd)
        api = client.get(f"/findings/{finding_row()[0]}/ticket").text + client.get("/integrations/jira").text
    assert jira_on.calls[0][2]["Authorization"] == f"Basic {basic}"           # sent to Jira only
    stored = json.dumps(tickets()) + json.dumps(audit_actions(""), default=str)
    for secret in (TOKEN, basic):
        assert secret not in caplog.text and secret not in stored and secret not in api
    assert TOKEN not in repr(service.settings())


def test_jira_outage_never_erases_or_changes_findings(client, make_asset, nvd, jira_on):
    asset = critical_asset(make_asset)
    jira_on.fail["search"] = [OSError("network unreachable")] * 5
    run = correlate(nvd)
    assert run.status == "success"
    items = client.get(f"/assets/{asset['id']}/findings").json()["items"]
    assert len(items) == 1 and items[0]["status"] == "open" and items[0]["ticket"]["state"] == "failed"
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(Finding)) == 1


@pytest.mark.parametrize("url", [
    "http://example.atlassian.net", "https://evil.example.com", "https://example.atlassian.net.evil.io",
    "https://user:pw@example.atlassian.net", "https://example.atlassian.net/rest", "https://10.0.0.1",
    "https://127.0.0.1", "https://example.atlassian.net:8443", "https://example.atlassian.net?x=1",
    "ftp://example.atlassian.net", "",
])
def test_base_url_is_restricted_to_jira_cloud(url):
    with pytest.raises(jira_mod.JiraConfigError):
        jira_mod.validate_base_url(url)


def test_valid_base_url_is_normalised():
    assert jira_mod.validate_base_url("https://example.atlassian.net/") == BASE


def test_redirects_are_not_followed():
    handler = jira_mod._NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example.com") is None


def test_configuration_errors_name_variables_not_values():
    with pytest.raises(jira_mod.JiraConfigError) as exc:
        jira_mod.build_settings(BASE, "ASSET", "bot@cybermock.io", "", "Task")
    assert "CAG_JIRA_API_TOKEN" in str(exc.value)
    for bad in ({"project_key": "bad key"}, {"label": "two words"}):
        args = {"base_url": BASE, "project_key": "ASSET", "email": "bot@cybermock.io", "api_token": TOKEN,
                "issue_type": "Task", **bad}
        with pytest.raises(jira_mod.JiraConfigError) as exc:
            jira_mod.build_settings(**args)
        assert TOKEN not in str(exc.value)


@pytest.mark.parametrize(("response", "error", "category"), [
    ((400, {}, b'{"errors": {"summary": "required"}}'), jira_mod.JiraPermanent, "invalid_request"),
    ((401, {}, b""), jira_mod.JiraPermanent, "authentication"),
    ((403, {}, b""), jira_mod.JiraPermanent, "permission"),
    ((429, {"Retry-After": "30"}, b""), jira_mod.JiraRetryable, "rate_limited"),
    ((502, {}, b""), jira_mod.JiraAmbiguous, "server"),
    ((201, {}, b'{"key": "not a key"}'), jira_mod.JiraAmbiguous, "malformed"),
    ((201, {}, b"x" * (jira_mod.MAX_RESPONSE_BYTES + 1)), jira_mod.JiraAmbiguous, "malformed"),
    (TimeoutError("slow"), jira_mod.JiraAmbiguous, "timeout"),
])
def test_client_classifies_jira_answers(response, error, category):
    def fetch(method, url, headers, body, timeout):
        if isinstance(response, Exception):
            raise response
        return response
    settings = jira_mod.build_settings(BASE, "ASSET", "bot@cybermock.io", TOKEN, "Task")
    with pytest.raises(error) as exc:
        jira_mod.JiraClient(settings, fetch).create_issue({"summary": "x"})
    assert exc.value.category == category and TOKEN not in str(exc.value)
    if category == "rate_limited":
        assert exc.value.retry_after == 30
    if category == "invalid_request":
        assert "summary: required" in str(exc.value)


def test_scan_scope_is_still_enforced(client):
    assert client.post("/monitoring/discover", json={"target": "8.8.8.8"}).status_code == 403


def test_jira_tickets_table_is_created_and_persists(make_asset, nvd, jira_on):
    critical_asset(make_asset)
    correlate(nvd)
    with session_scope() as db:                          # a fresh session reads the stored mapping
        t = db.scalars(select(JiraTicket)).one()
        assert (t.issue_key, t.issue_url, t.state, t.trigger) == ("ASSET-1", f"{BASE}/browse/ASSET-1", "created",
                                                                   "auto")
        assert t.created_at and t.last_attempt_at and t.synced_at and t.label.startswith("cag-")


def test_queueing_failure_never_leaves_the_assessment_running(make_asset, nvd, jira_on, monkeypatch, caplog):
    """Regression: a database error while queueing Jira tasks used to roll the finished run
    back to 'running', which blocked every further manual assessment until a restart."""
    from sqlalchemy.exc import OperationalError

    from app.correlation.engine import CorrelationBusy, queue_run
    from app.correlation.models import CorrelationRun

    def broken(*args, **kwargs):
        raise OperationalError("INSERT INTO jira_tickets", {}, Exception("database is locked"))
    monkeypatch.setattr(service, "enqueue_qualifying", broken)
    critical_asset(make_asset)
    with caplog.at_level(logging.ERROR):
        run = correlate(nvd)

    with session_scope() as db:
        stored = db.get(CorrelationRun, run.id)
        assert stored.status == "success" and stored.finished_at is not None      # not 'running'
        assert "Jira tasks not queued (OperationalError)" in stored.warnings
    assert "queueing Jira tasks after correlation run" in caplog.text            # recorded, not swallowed
    assert finding_row()[1] == FindingStatus.OPEN                                # the finding was kept
    assert tickets() == [] and jira_on.calls == []

    with session() as s:                                                         # a new manual run starts
        try:
            queued = queue_run(s, "manual")
        except CorrelationBusy as exc:
            pytest.fail(f"assessment stuck: {exc}")
        assert queued.status == "queued"


def test_failed_assessment_queues_no_jira_tasks(make_asset, nvd, jira_on, monkeypatch):
    calls = []
    monkeypatch.setattr(service, "enqueue_qualifying", lambda *a, **k: calls.append(a) or 0)
    monkeypatch.setattr(engine, "correlate_asset", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    critical_asset(make_asset)
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    with session() as s:
        run = engine.run_correlation(s, nvd)
    assert run.status == "failed" and calls == []                                # never reported as success

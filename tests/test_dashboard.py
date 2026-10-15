"""Executive dashboard: KPI semantics, month boundaries, history, health, access control."""
from datetime import UTC, date, datetime, timedelta

import pytest
from correlation_data import FakeNvd, add_version_scan, kev_fetch, session
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.audit.models import AuditEvent, Outcome
from app.correlation import engine, kev
from app.correlation.models import CorrelationRun, Finding
from app.dashboard import service
from app.dashboard.models import SecuritySnapshot

UTC = UTC
IP_A, IP_B = "10.0.0.5", "10.0.0.6"


@pytest.fixture
def nvd():
    return FakeNvd()


@pytest.fixture
def lab(make_asset):
    return make_asset(name="metasploitable", ip_address=IP_A, internet_facing="yes",
                      criticality="critical", environment="production")


@pytest.fixture
def office(make_asset):
    return make_asset(name="office-pc", ip_address=IP_B, internet_facing="no",
                      criticality="low", environment="test")


def correlate(nvd, **kwargs):
    with session() as s:
        return engine.run_correlation(s, nvd, **kwargs)


def dash(client, **params):
    r = client.get("/dashboard", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def set_first_seen(cve_id, when):
    with session() as s:
        for f in s.scalars(select(Finding).where(Finding.cve_id == cve_id)).unique():
            f.first_seen = when
        s.commit()


def finding_id(cve_id):
    with session() as s:
        return s.scalars(select(Finding.id).where(Finding.cve_id == cve_id)).first()


def audit(action, target_id, when):
    with session() as s:
        s.add(AuditEvent(occurred_at=when, actor_username="system", action=action, outcome=Outcome.SUCCESS,
                         target_type="finding", target_id=str(target_id)))
        s.commit()


def snapshot(day, **values):
    base = dict(taken_at=datetime.combine(day, datetime.max.time(), UTC).replace(microsecond=0),
                security_score=None, method_version=service.METHOD_VERSION, worst_asset_risk=None,
                assets_active=0, assets_assessed=0, assets_at_risk=0, open_findings=0, open_critical=0,
                open_high=0, open_medium=0, open_low=0, open_unscored=0)
    with session() as s:
        s.merge(SecuritySnapshot(day=day, **{**base, **values}))
        s.commit()


# --- empty database ---------------------------------------------------------------------------------------

def test_empty_database_shows_unavailable_not_zero_risk(client):
    d = dash(client)
    assert d["security_score"]["value"] is None
    assert d["security_score"]["unavailable_reason"] == "no asset with software data has been assessed yet"
    assert d["posture"]["assets_active"] == 0 and d["open_critical_now"] == 0
    assert d["month_figures"]["new_findings"] == 0 and d["month_figures"]["remediation_rate"] is None
    assert "snapshot" in d["month_figures"]["remediation_rate_reason"]
    assert len(d["series"]) == 12 and all(m["new"] == m["resolved"] == 0 for m in d["series"])
    assert d["trend"] == [] and d["top_risks"] == []
    assert d["health"]["last_run"] is None and d["health"]["last_full_assessment"] is None
    assert set(d["unavailable"]) == {"overdue_actions", "recommended_action"}
    assert d["timezone"] == "UTC" and "Security Score" in d["methodology"]


# --- Security Score ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("worst, at_risk, assessed, expected", [
    (0, 0, 5, 100),          # nothing open
    (90, 1, 10, 50),         # one critical asset of ten: 100 - (45 + 5)
    (94, 1, 2, 28),          # 100 - (47 + 25)
    (91, 0, 1, 54),          # 100 - 45.5 rounded half up -> 46
    (100, 4, 4, 0),
    (0, 0, 0, None),         # nothing assessed: unavailable, never "100"
])
def test_security_score_formula(worst, at_risk, assessed, expected):
    assert service.security_score(worst, at_risk, assessed) == expected
    assert service.security_score(worst, at_risk, assessed) == service.security_score(worst, at_risk, assessed)


def test_one_severe_risk_is_not_averaged_away():
    many_clean = service.security_score(95, 1, 100)       # 1 critical asset among 100
    assert many_clean <= 100 - 95 // 2


# --- current posture KPIs ------------------------------------------------------------------------------------

def test_kpis_match_the_stored_risk_and_the_linked_lists(client, make_asset, lab, office, nvd):
    make_asset(name="cloud-no-ip")                                     # no data: not assessed
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4"), (80, "Apache httpd", "2.4.49")])
    add_version_scan(IP_B, [(22, "OpenSSH", "7.4p1")])
    correlate(nvd)
    d = dash(client)
    p = d["posture"]
    assert (p["assets_active"], p["assets_assessed"], p["assets_no_data"]) == (3, 2, 1)

    unresolved = client.get("/findings", params={"unresolved": True, "active_assets": True, "limit": 500}).json()
    scores = [f["risk"]["score"] for f in unresolved["items"]]
    assert p["open_findings"] == unresolved["total"] == len(scores)
    by_level = {lvl: sum(f["risk"]["level"] == lvl for f in unresolved["items"]) for lvl in service.LEVELS}
    assert p["open_by_level"] == by_level
    at_risk = {f["asset_id"] for f in unresolved["items"] if f["risk"]["score"] >= 65}
    assert p["assets_at_risk"] == len(at_risk)
    assert p["worst_asset_risk"] == max(scores)
    assert d["security_score"]["value"] == service.security_score(max(scores), len(at_risk), 2)

    critical = client.get("/findings", params={"unresolved": True, "active_assets": True,
                                               "risk_level": "CRITICAL"}).json()
    assert d["open_critical_now"] == critical["total"] == by_level["CRITICAL"]
    high_plus = client.get("/findings", params={"unresolved": True, "active_assets": True, "min_risk": 65}).json()
    assert len({f["asset_id"] for f in high_plus["items"]}) == p["assets_at_risk"]


def test_accepted_inactive_and_in_remediation(client, lab, office, nvd):
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4")])
    add_version_scan(IP_B, [(22, "OpenSSH", "7.4p1")])
    correlate(nvd)
    before = dash(client)["posture"]["open_findings"]
    vsftpd = finding_id("CVE-2011-2523")
    client.patch(f"/findings/{vsftpd}", json={"status": "in_remediation"})
    assert dash(client)["posture"]["open_findings"] == before          # still unresolved
    client.patch(f"/findings/{vsftpd}", json={"status": "accepted_risk", "reason": "lab"})
    assert dash(client)["posture"]["open_findings"] == before - 1      # accepted is not open
    client.post(f"/assets/{office['id']}/deactivate")
    p = dash(client)["posture"]
    assert p["assets_active"] == 1 and p["open_findings"] == 0


# --- monthly semantics ------------------------------------------------------------------------------------

def test_month_and_year_boundaries(client, lab, nvd):
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4"), (80, "Apache httpd", "2.4.49")])
    correlate(nvd)
    set_first_seen("CVE-2011-2523", datetime(2025, 12, 31, 23, 59, 59, tzinfo=UTC))
    set_first_seen("CVE-2021-41773", datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC))
    set_first_seen("CVE-2099-0002", datetime(2026, 1, 31, 23, 59, 59, tzinfo=UTC))
    with session() as s:
        assert service.month_figures(s, 2025, 12)["new_findings"] == 1
        assert service.month_figures(s, 2026, 1)["new_findings"] == 2
        assert service.month_figures(s, 2026, 2)["new_findings"] == 0
        series = {m["month"]: m["new"] for m in service.monthly_series(s, 2026, 2)}
    assert (series["2025-12"], series["2026-01"], series["2026-02"]) == (1, 2, 0)
    assert len(series) == 12 and list(series)[0] == "2025-03"


def test_month_bounds_and_parsing():
    assert service.month_bounds(2025, 12) == (datetime(2025, 12, 1, tzinfo=UTC), datetime(2026, 1, 1, tzinfo=UTC))
    assert service.previous_month(2026, 1) == (2025, 12)
    now = datetime(2026, 10, 14, tzinfo=UTC)
    assert service.parse_month(None, now) == (2026, 10)
    assert service.parse_month("2026-01", now) == (2026, 1)
    for bad in ("2026-13", "26-01", "2026-1", "abc", "2026-11", "1999-12"):
        with pytest.raises(service.InvalidPeriod):
            service.parse_month(bad, now)


def test_repeated_observations_and_reopen_do_not_count_as_new(client, lab, nvd):
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4")])                 # observed again
    correlate(nvd)
    add_version_scan(IP_A, [(21, "vsftpd", "3.0.5")])                 # fixed -> auto_close
    correlate(nvd)
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4")])                 # regression -> auto_reopen
    correlate(nvd)
    m = dash(client)["month_figures"]
    assert (m["new_findings"], m["resolved_findings"], m["reopened_findings"]) == (1, 1, 1)


def test_resolved_counts_distinct_findings_from_the_audit_log(client, lab, nvd):
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4"), (80, "Apache httpd", "2.4.49")])
    correlate(nvd)
    a, b = finding_id("CVE-2011-2523"), finding_id("CVE-2021-41773")
    audit("finding.auto_close", a, datetime(2026, 3, 2, tzinfo=UTC))
    audit("finding.auto_close", a, datetime(2026, 3, 20, tzinfo=UTC))   # closed twice: counted once
    audit("finding.auto_close", b, datetime(2026, 4, 1, tzinfo=UTC))    # April
    audit("finding.update", b, datetime(2026, 3, 5, tzinfo=UTC))        # not a resolution
    with session() as s:
        assert service.month_figures(s, 2026, 3)["resolved_findings"] == 1
        assert service.month_figures(s, 2026, 4)["resolved_findings"] == 1


def test_remediation_rate_needs_a_start_of_month_snapshot(client, lab, nvd):
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    f = finding_id("CVE-2011-2523")
    set_first_seen("CVE-2011-2523", datetime(2026, 3, 10, tzinfo=UTC))
    audit("finding.auto_close", f, datetime(2026, 3, 11, tzinfo=UTC))
    with session() as s:
        m = service.month_figures(s, 2026, 3)
    assert m["remediation_rate"] is None and "snapshot" in m["remediation_rate_reason"]
    snapshot(date(2026, 2, 10), open_findings=9)                        # nothing changed since: still the state
    with session() as s:
        assert service.month_figures(s, 2026, 3)["remediation_rate"] == 10.0     # 1 / (9 + 1)
    snapshot(date(2026, 3, 2), open_findings=50)                        # inside March: not a start value
    snapshot(date(2026, 2, 28), open_findings=3)                        # latest before March wins
    with session() as s:
        m = service.month_figures(s, 2026, 3)
    assert (m["unresolved_at_start"], m["remediation_workload"], m["resolved_findings"]) == (3, 4, 1)
    assert m["remediation_rate"] == 25.0                                # 1 / (3 + 1 new + 0 reopened)


def test_current_vs_previous_month_and_score_change(client, lab, nvd):
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    now = datetime.now(UTC)
    py, pm = service.previous_month(now.year, now.month)
    set_first_seen("CVE-2011-2523", datetime(py, pm, 15, tzinfo=UTC))
    start = service.month_bounds(now.year, now.month)[0].date()
    snapshot(start - timedelta(days=1), security_score=80, open_findings=1)
    d = dash(client)
    assert d["month_figures"]["new_findings"] == 0 and d["previous_month_figures"]["new_findings"] == 1
    score = d["security_score"]
    assert score["baseline"] == 80 and score["change"] == score["value"] - 80
    snapshot(start - timedelta(days=1), security_score=80, method_version="0")
    assert dash(client)["security_score"]["change"] is None             # different method: no comparison


def test_past_month_uses_only_persisted_snapshots(client, lab, nvd):
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    now = datetime.now(UTC)
    py, pm = service.previous_month(now.year, now.month)
    d = dash(client, month=f"{py:04d}-{pm:02d}")
    assert d["security_score"]["value"] is None                         # never recomputed for the past
    assert d["security_score"]["unavailable_reason"] == "no posture snapshot recorded in this month"
    snapshot(date(py, pm, 20), security_score=61)
    assert dash(client, month=f"{py:04d}-{pm:02d}")["security_score"]["value"] == 61


# --- history mechanism ------------------------------------------------------------------------------------

def test_snapshots_are_recorded_once_per_day_from_real_events(client, lab, nvd):
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    correlate(nvd)
    with session() as s:
        kev.refresh(s, fetch=kev_fetch())
    trend = dash(client)["trend"]
    assert len(trend) == 1 and trend[0]["day"] == datetime.now(UTC).date().isoformat()
    assert trend[0]["open_critical"] == dash(client)["open_critical_now"]
    assert trend[0]["security_score"] == dash(client)["security_score"]["value"]


# --- top risks ------------------------------------------------------------------------------------------

def test_top_risks_follow_the_findings_risk_order(client, lab, office, nvd):
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4"), (80, "Apache httpd", "2.4.49")])
    add_version_scan(IP_B, [(22, "OpenSSH", "7.4p1")])
    correlate(nvd)
    top = dash(client)["top_risks"]
    ranked = client.get("/findings", params={"unresolved": True, "active_assets": True, "sort": "risk",
                                             "limit": 5}).json()["items"]
    assert [t["finding_id"] for t in top] == [f["id"] for f in ranked if f["risk"]][:5]
    first = top[0]
    assert (first["asset_name"], first["criticality"], first["internet_facing"]) == ("metasploitable", "critical", "yes")
    assert first["recommended_action"] is None and first["nvd_url"].endswith(first["cve_id"])
    assert client.get(f"/assets/{first['asset_id']}").status_code == 200        # link target exists


# --- assessment health ------------------------------------------------------------------------------------

def test_partial_and_failed_runs_are_never_shown_as_success(client, lab, nvd):
    now = datetime.now(UTC)
    with session() as s:
        s.add_all([
            CorrelationRun(trigger="scheduled", status="success", scope=None, started_at=now - timedelta(days=3),
                           finished_at=now - timedelta(days=3)),                          # legacy full run
            CorrelationRun(trigger="manual", status="failed", scope="all", started_at=now - timedelta(days=2),
                           finished_at=now - timedelta(days=2), warnings="RuntimeError: boom"),
            CorrelationRun(trigger="manual", status="partial", scope="selected", started_at=now - timedelta(days=1),
                           finished_at=now - timedelta(days=1), warnings="a: NVD unreachable\nb: x"),
        ])
        s.commit()
    h = dash(client)["health"]
    assert (h["last_run"]["status"], h["last_run"]["scope"]) == ("partial", "selected")
    assert h["last_run"]["warnings_count"] == 2
    assert (h["last_full_assessment"]["status"], h["last_full_assessment"]["scope"]) == ("failed", "all")
    assert [r["status"] for r in h["recent_problem_runs"]] == ["partial", "failed"]


def test_new_runs_record_their_scope(client, lab, office, nvd):
    full = correlate(nvd)
    subset = correlate(nvd, asset_ids=[lab["id"]])
    assert (full.scope, subset.scope) == ("all", "selected")
    h = dash(client)["health"]
    assert h["last_full_assessment"]["id"] == full.id and h["last_run"]["id"] == subset.id


# --- access control and input validation ------------------------------------------------------------------------

def test_access_control_and_validation(app, client, client_as):
    assert TestClient(app).get("/dashboard").status_code == 401
    assert client_as("viewer").get("/dashboard").status_code == 200
    for bad in ("2026-13", "abc", "1999-12", "9999-01"):
        assert client.get("/dashboard", params={"month": bad}).status_code == 422


def test_findings_filters_used_by_dashboard_links(client, lab, nvd):
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4"), (80, "Apache httpd", "2.4.49")])
    correlate(nvd)
    set_first_seen("CVE-2011-2523", datetime(2026, 1, 15, tzinfo=UTC))
    jan = client.get("/findings", params={"first_seen_from": "2026-01-01", "first_seen_to": "2026-02-01"}).json()
    assert [f["cve"]["id"] for f in jan["items"]] == ["CVE-2011-2523"]
    assert client.get("/findings", params={"risk_level": "bogus"}).status_code == 422
    assert client.get("/findings", params={"min_risk": 101}).status_code == 422


def test_score_stays_in_range_when_open_findings_sit_on_assets_without_data(client, make_asset, nvd):
    """Review finding: findings kept open on an asset that lost its software data must not enter
    W / B while the asset is excluded from the denominator (the score went to -45)."""
    from app.assets.models import Asset
    from app.audit.service import SYSTEM
    from app.correlation.service import add_software, list_software, remove_software
    clean = make_asset(name="clean", ip_address=IP_B)
    add_version_scan(IP_B, [(21, "vsftpd", "3.0.5")])                  # assessed, nothing found
    manual = [make_asset(name=f"manual-{i}") for i in range(2)]
    with session() as s:
        for a in manual:
            add_software(s, SYSTEM, s.get(Asset, a["id"]), "vsftpd", "2.3.4", None)
    correlate(nvd)
    with session() as s:                                                 # data removed, findings stay open
        for a in manual:
            asset = s.get(Asset, a["id"])
            for sw in list_software(s, asset):
                remove_software(s, SYSTEM, asset, sw.id)
    correlate(nvd)
    p = dash(client)["posture"]
    assert (p["assets_assessed"], p["assets_no_data"], p["open_outside_score"]) == (1, 2, 2)
    assert p["assets_at_risk"] == 0 and dash(client)["security_score"]["value"] == 100
    assert p["open_findings"] == 2                                       # still visible as open
    assert clean["id"]


def test_a_failing_snapshot_never_breaks_the_caller(client, lab, nvd, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("snapshot failed")
    monkeypatch.setattr(service, "record_snapshot", boom)
    add_version_scan(IP_A, [(21, "vsftpd", "2.3.4")])
    run = correlate(nvd)
    assert run.status in ("success", "partial")
    fid = finding_id("CVE-2011-2523")
    assert client.patch(f"/findings/{fid}", json={"status": "in_remediation"}).status_code == 200
    assert client.patch(f"/assets/{lab['id']}", json={"criticality": "low"}).status_code == 200

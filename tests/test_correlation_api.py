"""Findings / correlation API: filters, status changes, permissions and audit log."""
import pytest
from correlation_data import FakeNvd, add_version_scan, session

from app.correlation import engine, jobs

IP = "10.0.0.5"


@pytest.fixture
def nvd(monkeypatch):
    fake = FakeNvd()
    monkeypatch.setattr(jobs, "nvd_client", lambda: fake)
    return fake


@pytest.fixture
def lab(client, make_asset, nvd):
    asset = make_asset(name="metasploitable", ip_address=IP)
    add_version_scan(IP, [(21, "vsftpd", "2.3.4"), (22, "OpenSSH", "4.7p1 Debian 8ubuntu1"),
                          (80, "Apache httpd", "2.4.49")])
    r = client.post("/correlation/run")
    assert r.status_code == 202 and r.json()["status"] == "queued"
    run = client.get(f"/correlation/runs/{r.json()['id']}").json()   # ran in the background
    assert run["status"] == "success" and run["findings_opened"] == 5, run
    return asset


def test_list_sorted_and_filtered(client, lab):
    # CVSS order; the default (contextual risk) is covered in test_risk_findings.py
    page = client.get("/findings", params={"sort": "cvss"}).json()
    assert page["total"] == 5
    assert page["items"][0]["cve"]["id"] == "CVE-2011-2523"               # highest CVSS first
    assert page["items"][0]["cve"]["nvd_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"
    assert page["items"][0]["asset_name"] == "metasploitable"
    assert page["items"][-1]["cve"]["severity"] == "UNKNOWN"
    assert [i["cve"]["id"] for i in client.get("/findings", params={"severity": "CRITICAL"}).json()["items"]] \
        == ["CVE-2011-2523"]
    assert client.get("/findings", params={"kev": True}).json()["total"] == 0
    assert client.get("/findings", params={"cve": "cve-2021-41773"}).json()["total"] == 1
    assert len(client.get("/findings", params={"limit": 2, "offset": 4}).json()["items"]) == 1
    assert client.get("/findings", params={"severity": "bogus"}).status_code == 422


def test_asset_findings_and_detail(client, lab):
    page = client.get(f"/assets/{lab['id']}/findings").json()
    assert page["total"] == 5
    detail = client.get(f"/findings/{page['items'][0]['id']}").json()
    assert detail["asset_id"] == lab["id"] and detail["port"] == 21
    assert client.get("/findings/99999").status_code == 404
    assert client.get("/assets/not-a-uuid/findings").status_code == 404


def test_status_changes_and_risk_acceptance(client, lab):
    fid = client.get("/findings").json()["items"][0]["id"]
    r = client.patch(f"/findings/{fid}", json={"status": "in_remediation", "ticket_key": "ASSET-123"})
    assert r.status_code == 200 and r.json()["ticket_key"] == "ASSET-123"

    r = client.patch(f"/findings/{fid}", json={"status": "accepted_risk"})
    assert r.status_code == 422 and "reason" in r.json()["detail"]
    r = client.patch(f"/findings/{fid}", json={"status": "accepted_risk", "reason": "isolated lab VM"})
    assert r.json()["status"] == "accepted_risk" and r.json()["status_reason"] == "isolated lab VM"

    assert client.patch(f"/findings/{fid}", json={"status": "resolved"}).status_code == 422

    events = client.get("/audit", params={"target_type": "finding"}).json()["items"]
    actions = [e["action"] for e in events]
    assert actions[0] == "finding.accept_risk" and "finding.update" in actions
    assert events[0]["details"]["status"] == {"from": "in_remediation", "to": "accepted_risk"}


def test_manual_software(client, make_asset, nvd):
    asset = make_asset(name="appserver")
    r = client.post(f"/assets/{asset['id']}/software", json={"product": " OpenSSH ", "version": "9.6p1"})
    assert r.status_code == 201 and r.json()["product"] == "OpenSSH"
    assert [s["product"] for s in client.get(f"/assets/{asset['id']}/software").json()] == ["OpenSSH"]

    client.post("/correlation/run", json={"asset_ids": [asset["id"]]})
    assert client.get(f"/assets/{asset['id']}/findings").json()["items"][0]["cve"]["id"] == "CVE-2024-6387"

    assert client.delete(f"/assets/{asset['id']}/software/{r.json()['id']}").status_code == 204
    assert client.delete(f"/assets/{asset['id']}/software/{r.json()['id']}").status_code == 404
    actions = [e["action"] for e in client.get("/audit", params={"action": "asset.software_*"}).json()["items"]]
    assert actions == ["asset.software_remove", "asset.software_add"]


def test_runs_are_listed_and_audited(client, lab):
    runs = client.get("/correlation/runs").json()
    assert runs[0]["trigger"] == "manual" and runs[0]["assets_processed"] == 1
    assert client.get("/audit", params={"action": "correlation.run"}).json()["total"] == 1


@pytest.mark.parametrize("method, path, body, viewer, analyst", [
    ("GET", "/findings", None, 200, 200),
    ("GET", "/correlation/runs", None, 200, 200),
    ("POST", "/correlation/run", {}, 403, 202),
    ("PATCH", "/findings/1", {"status": "in_remediation"}, 403, 200),
])
def test_permissions(client_as, lab, method, path, body, viewer, analyst):
    assert client_as("viewer").request(method, path, json=body).status_code == viewer
    assert client_as("analyst").request(method, path, json=body).status_code == analyst


def test_viewer_cannot_add_software(client_as, lab):
    r = client_as("viewer").post(f"/assets/{lab['id']}/software", json={"product": "nginx"})
    assert r.status_code == 403


def test_scan_hook_schedules_background_correlation(monkeypatch):
    from app import config
    from app.monitoring import scheduler

    added = []

    class FakeScheduler:
        running = True

        def add_job(self, func, **kwargs):
            added.append((func, kwargs))

    monkeypatch.setattr(scheduler, "get_scheduler", lambda: FakeScheduler())
    jobs.schedule_after_scan(7)
    assert added == []                                    # disabled in tests by conftest
    monkeypatch.setattr(config, "CORRELATION_AFTER_SCAN", True)
    jobs.schedule_after_scan(7)
    assert added[0][0] is jobs.correlate_after_scan and added[0][1]["args"] == [7]


def test_correlate_after_scan_uses_the_scanned_assets(lab, monkeypatch):
    called = {}
    monkeypatch.setattr(jobs, "nvd_client", lambda: FakeNvd())
    monkeypatch.setattr(jobs.engine, "run_correlation",
                        lambda s, nvd, ids, trigger: called.update(ids=ids, trigger=trigger))
    scan_id = add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    jobs.correlate_after_scan(scan_id)
    assert called == {"ids": [lab["id"]], "trigger": "scan"}


def test_second_run_is_refused_while_one_is_active(client, nvd):
    with session() as s:
        queued = engine.queue_run(s, trigger="manual")
    r = client.post("/correlation/run")
    assert r.status_code == 409 and str(queued.id) in r.json()["detail"]
    assert client.get("/correlation/runs/99999").status_code == 404


def test_interrupted_runs_are_swept_at_startup(client, nvd):
    with session() as s:
        queued = engine.queue_run(s, trigger="manual")
    jobs.on_startup()
    run = client.get(f"/correlation/runs/{queued.id}").json()
    assert run["status"] == "failed" and "interrupted" in run["warnings"]
    assert client.post("/correlation/run").status_code == 202      # no longer blocked


def test_automatic_status_changes_are_audited(client, lab, nvd):
    add_version_scan(IP, [(21, "vsftpd", "3.0.5"), (22, "OpenSSH", "4.7p1 Debian 8ubuntu1"),
                          (80, "Apache httpd", "2.4.49")])
    client.post("/correlation/run")
    events = client.get("/audit", params={"action": "finding.auto_close"}).json()["items"]
    assert len(events) == 1 and events[0]["actor_username"] == "system"
    assert events[0]["details"]["status"] == {"from": "open", "to": "resolved"}

    add_version_scan(IP, [(21, "vsftpd", "2.3.4"), (22, "OpenSSH", "4.7p1 Debian 8ubuntu1"),
                          (80, "Apache httpd", "2.4.49")])
    client.post("/correlation/run")
    assert client.get("/audit", params={"action": "finding.auto_reopen"}).json()["total"] == 1


@pytest.mark.parametrize("method, path", [
    ("GET", "/findings"), ("GET", "/findings/1"), ("PATCH", "/findings/1"), ("GET", "/correlation/runs"),
    ("GET", "/correlation/runs/1"), ("POST", "/correlation/run"), ("POST", "/correlation/kev/refresh"),
])
def test_every_correlation_endpoint_requires_login(anon_client, method, path):
    assert anon_client.request(method, path, json={}).status_code == 401

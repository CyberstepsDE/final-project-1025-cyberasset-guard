"""Step 4: assessment history, risk overview and schedule / status API."""
import pytest
from correlation_data import FakeNvd, add_version_scan, kev_fetch, session
from fastapi.testclient import TestClient

from app.correlation import engine, kev

IP = "10.0.0.5"


@pytest.fixture
def nvd():
    return FakeNvd()


@pytest.fixture
def lab(make_asset):
    return make_asset(name="metasploitable", ip_address=IP, internet_facing="yes",
                      criticality="critical", environment="production")


def correlate(nvd):
    with session() as s:
        return engine.run_correlation(s, nvd)


def history(client, asset_id):
    r = client.get(f"/assets/{asset_id}/risk/history")
    assert r.status_code == 200, r.text
    return r.json()


def test_history_records_each_risk_change_with_its_trigger(client, lab, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4"), (80, "Apache httpd", "2.4.49")])
    run = correlate(nvd)
    first = history(client, lab["id"])
    assert len(first) == 1
    assert (first[0]["trigger"], first[0]["run_id"], first[0]["max_score"]) == ("correlation", run.id, 94)

    correlate(nvd)                                                   # nothing changed: no new entry
    assert len(history(client, lab["id"])) == 1

    with session() as s:
        kev.refresh(s, fetch=kev_fetch())                            # vsftpd is in KEV -> 99
    entries = history(client, lab["id"])
    assert (entries[0]["trigger"], entries[0]["max_score"], entries[0]["run_id"]) == ("kev_refresh", 99, None)

    top = client.get("/findings").json()["items"][0]
    client.patch(f"/findings/{top['id']}", json={"status": "accepted_risk", "reason": "isolated lab"})
    assert history(client, lab["id"])[0]["trigger"] == "finding_status"
    assert history(client, lab["id"])[0]["accepted_findings"] == 1

    client.patch(f"/assets/{lab['id']}", json={"environment": "test"})
    latest = history(client, lab["id"])
    assert latest[0]["trigger"] == "asset_change" and latest[0]["max_score"] < latest[1]["max_score"]
    assert [e["recorded_at"] for e in latest] == sorted((e["recorded_at"] for e in latest), reverse=True)


def test_history_of_a_fix(client, lab, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    add_version_scan(IP, [(21, "vsftpd", "3.0.5")])
    correlate(nvd)
    entries = history(client, lab["id"])
    assert [(e["max_score"], e["open_findings"]) for e in entries] == [(None, 0), (94, 1)]


def test_risk_overview_lists_assessed_assets_only(client, make_asset, lab, nvd):
    no_data = make_asset(name="no-data")                             # no IP, no manual software
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    run = correlate(nvd)
    assert run.status == "success" and not run.warnings              # "no data" is not a run problem
    never = make_asset(name="created-after-the-run")
    client.post(f"/assets/{lab['id']}/deactivate")
    rows = {r["asset_id"]: r for r in client.get("/risk/assets").json()}
    assert lab["id"] in rows and never["id"] not in rows
    assert (rows[lab["id"]]["max_score"], rows[lab["id"]]["asset_status"]) == (94, "inactive")
    assert rows[lab["id"]]["correlation_warnings"] == []
    # "nothing could be checked" is reported on the asset, never shown as a clean result
    assert rows[no_data["id"]]["max_score"] is None
    (warning,) = rows[no_data["id"]]["correlation_warnings"]
    assert warning.startswith(engine.NO_SOFTWARE_PREFIX) and "no IP address" in warning


@pytest.mark.parametrize("ip, scan, expected", [
    ("10.0.0.9", None, "no completed version scan of 10.0.0.9"),
    ("10.0.0.9", [(80, None, None)], "the latest version scan identified no software"),
])
def test_no_data_message_says_why(client, make_asset, nvd, ip, scan, expected):
    asset = make_asset(name="quiet", ip_address=ip)
    if scan is not None:
        add_version_scan(ip, scan)
    correlate(nvd)
    (warning,) = client.get(f"/assets/{asset['id']}/risk").json()["correlation_warnings"]
    assert expected in warning


def test_data_arriving_later_is_a_history_entry(client, make_asset, nvd):
    asset = make_asset(name="late", ip_address="10.0.0.9")
    correlate(nvd)                                                   # nothing could be checked
    add_version_scan("10.0.0.9", [(21, "vsftpd", "3.0.5")])          # checked: not affected
    correlate(nvd)
    entries = history(client, asset["id"])
    assert len(entries) == 2
    assert entries[0]["correlation_warnings"] == [] and entries[1]["correlation_warnings"] != []
    assert entries[0]["max_score"] is None and entries[1]["max_score"] is None


def test_a_scoring_failure_leaves_no_history_entry(client, lab, nvd, monkeypatch):
    from app.risk import service as risk
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    real = risk._record_history

    def record_then_fail(*args, **kwargs):
        real(*args, **kwargs)
        raise RuntimeError("boom")
    add_version_scan(IP, [(21, "vsftpd", "3.0.5")])                 # fixed: the risk would change
    monkeypatch.setattr(risk, "_record_history", record_then_fail)
    run = correlate(nvd)
    assert "risk scoring failed" in run.warnings
    assert len(history(client, lab["id"])) == 1                      # the savepoint dropped the entry


def test_schedule_status(client, lab, nvd):
    status = client.get("/correlation/schedule").json()
    assert set(status) >= {"periodic_enabled", "interval_hours", "next_run_at", "after_scan",
                           "nvd_api_key_configured", "kev_current", "active_run", "last_run"}
    assert (status["kev_current"], status["last_run"], status["active_run"]) == (False, None, None)

    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    run = correlate(nvd)
    with session() as s:
        kev.refresh(s, fetch=kev_fetch())
    status = client.get("/correlation/schedule").json()
    assert status["kev_current"] is True and status["kev_entries"] == 1
    assert (status["last_run"]["id"], status["last_run"]["status"]) == (run.id, "success")


def test_schedule_shows_a_queued_run_as_active(client, lab):
    with session() as s:
        queued = engine.queue_run(s, trigger="manual")
    status = client.get("/correlation/schedule").json()
    assert status["active_run"]["id"] == queued.id and status["last_run"] is None


def test_permissions(app, client, client_as, lab):
    viewer = client_as("viewer")
    for path in ("/correlation/schedule", "/risk/assets", f"/assets/{lab['id']}/risk/history"):
        assert viewer.get(path).status_code == 200
        assert TestClient(app).get(path).status_code == 401
    assert client.get("/assets/not-a-uuid/risk/history").status_code == 404
    assert client.get(f"/assets/{lab['id']}/risk/history", params={"limit": 501}).status_code == 422

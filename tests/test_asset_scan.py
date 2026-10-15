"""On-demand scan and per-asset scheduling from the UI (ASSET-66).

The scanner is faked (no real nmap). Scheduled jobs are not actually registered with
APScheduler (the schedule row is what these tests care about), so nothing runs on a
background thread during the test.
"""
import uuid

import pytest

from app.monitoring import scanner, scheduler

UP = ('<nmaprun><host><status state="up" reason="syn-ack"/>'
      '<address addr="{ip}" addrtype="ipv4"/>'
      '<ports><port protocol="tcp" portid="22"><state state="open"/>'
      '<service name="ssh" product="OpenSSH" version="8.9"/></port></ports></host></nmaprun>')


@pytest.fixture
def fake_nmap(monkeypatch):
    holder = {"xml": "<nmaprun></nmaprun>"}
    monkeypatch.setattr(scanner, "_run_nmap", lambda args: holder["xml"])
    return holder


@pytest.fixture
def no_live_jobs(monkeypatch):
    """Persist schedule rows without registering a live APScheduler job."""
    monkeypatch.setattr(scheduler, "_add_job", lambda *a, **k: None)


# --- scan now ---------------------------------------------------------------

def test_scan_asset_runs_and_links(client, make_asset, fake_nmap):
    asset = make_asset(name="web", ip_address="10.0.0.5")
    fake_nmap["xml"] = UP.format(ip="10.0.0.5")
    r = client.post(f"/monitoring/assets/{asset['id']}/scan", json={"scan_type": "version"})
    assert r.status_code == 200, r.text
    assert r.json()["scan_type"] == "version"
    # the scan auto-links the discovered host, so the asset summary now shows the result
    summary = client.get(f"/monitoring/assets/{asset['id']}/summary").json()
    assert summary["scanned"] is True
    assert any(p["port"] == 22 for p in summary["ports"])


def test_scan_asset_without_target_is_422(client, make_asset, fake_nmap):
    asset = make_asset(name="no-network")            # no IP or hostname
    r = client.post(f"/monitoring/assets/{asset['id']}/scan", json={"scan_type": "discovery"})
    assert r.status_code == 422


def test_scan_unknown_asset_is_404(client):
    r = client.post(f"/monitoring/assets/{uuid.uuid4()}/scan", json={"scan_type": "discovery"})
    assert r.status_code == 404


def test_scan_asset_reports_nmap_missing(client, make_asset, monkeypatch):
    asset = make_asset(name="web", ip_address="10.0.0.5")

    def boom(args):
        raise scanner.ScannerError("nmap binary 'nmap' not found on PATH.")

    monkeypatch.setattr(scanner, "_run_nmap", boom)
    r = client.post(f"/monitoring/assets/{asset['id']}/scan", json={"scan_type": "discovery"})
    assert r.status_code == 502 and "nmap" in r.json()["detail"]


def test_scan_requires_monitoring_run(client, client_as, make_asset, fake_nmap):
    asset = make_asset(name="web", ip_address="10.0.0.5")   # created by the admin client fixture
    assert client_as("viewer").post(f"/monitoring/assets/{asset['id']}/scan",
                                    json={"scan_type": "discovery"}).status_code == 403


# --- per-asset schedules ----------------------------------------------------

def test_asset_schedule_create_list_remove(client, make_asset, no_live_jobs):
    asset = make_asset(name="web", ip_address="10.0.0.5")
    created = client.post(f"/monitoring/assets/{asset['id']}/schedules",
                          json={"scan_type": "version", "interval_seconds": 3600})
    assert created.status_code == 200, created.text
    sched_id = created.json()["id"]

    listed = client.get(f"/monitoring/assets/{asset['id']}/schedules").json()
    assert [s["id"] for s in listed] == [sched_id]
    assert listed[0]["target"] == "10.0.0.5"

    assert client.delete(f"/monitoring/schedules/{sched_id}").status_code == 200
    assert client.get(f"/monitoring/assets/{asset['id']}/schedules").json() == []


def test_asset_schedule_below_minimum_interval_is_422(client, make_asset):
    asset = make_asset(name="web", ip_address="10.0.0.5")
    r = client.post(f"/monitoring/assets/{asset['id']}/schedules",
                    json={"scan_type": "version", "interval_seconds": 5})
    assert r.status_code == 422


def test_asset_schedule_requires_monitoring_run(client, client_as, make_asset):
    asset = make_asset(name="web", ip_address="10.0.0.5")
    assert client_as("viewer").post(f"/monitoring/assets/{asset['id']}/schedules",
                                    json={"scan_type": "version", "interval_seconds": 3600}).status_code == 403

"""Concurrent-scan limit — CAG_SCAN_MAX_CONCURRENT (ASSET-62 / B4.2).

Scans over the limit are rejected with HTTP 429 instead of overloading the host/DB.
The scanner is faked; the limit is a per-process counter, reset around each test.
"""
import pytest

from app import config
from app.monitoring import scanner, service

HOST_XML = '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/></host></nmaprun>'


@pytest.fixture
def fake_nmap(monkeypatch):
    monkeypatch.setattr(scanner, "_run_nmap", lambda args: HOST_XML)


@pytest.fixture(autouse=True)
def reset_slots():
    service._active_scans = 0
    yield
    service._active_scans = 0


def test_scan_rejected_when_at_capacity(client, make_asset, monkeypatch, fake_nmap):
    monkeypatch.setattr(config, "SCAN_MAX_CONCURRENT", 1)
    asset = make_asset(name="web", ip_address="10.0.0.5")
    service._acquire_scan_slot()                           # simulate one scan already running
    r = client.post(f"/monitoring/assets/{asset['id']}/scan", json={"scan_type": "discovery"})
    assert r.status_code == 429, r.text
    assert "too many scans" in r.json()["detail"].lower()


def test_slot_is_released_after_each_scan(client, make_asset, monkeypatch, fake_nmap):
    monkeypatch.setattr(config, "SCAN_MAX_CONCURRENT", 1)
    asset = make_asset(name="web", ip_address="10.0.0.5")
    for _ in range(3):                                     # sequential scans reuse the single slot
        assert client.post(f"/monitoring/assets/{asset['id']}/scan",
                           json={"scan_type": "discovery"}).status_code == 200
    assert service._active_scans == 0


def test_slot_released_even_when_the_scan_fails(client, make_asset, monkeypatch):
    monkeypatch.setattr(config, "SCAN_MAX_CONCURRENT", 1)

    def boom(args):
        raise scanner.ScannerError("nmap binary 'nmap' not found on PATH.")

    monkeypatch.setattr(scanner, "_run_nmap", boom)
    asset = make_asset(name="web", ip_address="10.0.0.5")
    assert client.post(f"/monitoring/assets/{asset['id']}/scan",
                       json={"scan_type": "discovery"}).status_code == 502
    assert service._active_scans == 0                      # slot freed despite the failure


def test_acquire_raises_when_full(monkeypatch):
    monkeypatch.setattr(config, "SCAN_MAX_CONCURRENT", 2)
    service._acquire_scan_slot()
    service._acquire_scan_slot()
    with pytest.raises(service.ScanBusyError):
        service._acquire_scan_slot()
    service._release_scan_slot()
    service._release_scan_slot()
    service._acquire_scan_slot()                           # a freed slot can be reused
    assert service._active_scans == 1

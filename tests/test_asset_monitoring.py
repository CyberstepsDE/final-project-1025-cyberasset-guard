"""Monitoring summary on the asset detail page (ASSET-65).

Drives the real scan pipeline with a faked nmap so a discovered host is created,
auto-linked to a managed asset, and its reachability/ports/changes are persisted;
then checks the GET /monitoring/assets/{asset_id}/summary endpoint.
"""
import pytest

from app.monitoring import scanner, service

UP_WITH_PORTS = (
    '<nmaprun><host><status state="up" reason="syn-ack"/>'
    '<address addr="{ip}" addrtype="ipv4"/>'
    '<times srtt="1500"/>'
    "<ports>{ports}</ports></host></nmaprun>"
)
PORT = ('<port protocol="tcp" portid="{portid}"><state state="open"/>'
        '<service name="{name}" product="{product}" version="{version}"/></port>')


@pytest.fixture
def fake_nmap(monkeypatch):
    holder = {"xml": "<nmaprun></nmaprun>"}
    monkeypatch.setattr(scanner, "_run_nmap", lambda args: holder["xml"])
    return holder


def _version_scan(fake_nmap, ip, ports_xml):
    fake_nmap["xml"] = UP_WITH_PORTS.format(ip=ip, ports=ports_xml)
    return service.run_version_scan(ip)


def test_summary_not_scanned_when_no_linked_host(client, make_asset):
    asset = make_asset(name="fresh", ip_address="10.0.0.5")
    r = client.get(f"/monitoring/assets/{asset['id']}/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["linked"] is False and body["scanned"] is False
    assert body["reachability"] is None
    assert body["ports"] == [] and body["recent_changes"] == []


def test_summary_shows_reachability_and_ports(client, make_asset, fake_nmap):
    asset = make_asset(name="web", ip_address="10.0.0.5")
    _version_scan(fake_nmap, "10.0.0.5",
                  PORT.format(portid=22, name="ssh", product="OpenSSH", version="8.9"))

    body = client.get(f"/monitoring/assets/{asset['id']}/summary").json()
    assert body["linked"] is True and body["scanned"] is True
    assert body["reachability"]["state"] == "up"
    assert body["reachability"]["ip"] == "10.0.0.5"
    assert body["last_scan"]["scan_type"] == "version"
    assert len(body["ports"]) == 1
    port = body["ports"][0]
    assert port["port"] == 22 and port["protocol"] == "tcp"
    assert port["service"] == "ssh" and port["product"] == "OpenSSH" and port["version"] == "8.9"


def test_summary_lists_recent_changes(client, make_asset, fake_nmap):
    asset = make_asset(name="web", ip_address="10.0.0.5")
    _version_scan(fake_nmap, "10.0.0.5",
                  PORT.format(portid=22, name="ssh", product="OpenSSH", version="8.9"))
    # A later scan opens port 80 — change detection should record it.
    _version_scan(fake_nmap, "10.0.0.5",
                  PORT.format(portid=22, name="ssh", product="OpenSSH", version="8.9")
                  + PORT.format(portid=80, name="http", product="nginx", version="1.25"))

    body = client.get(f"/monitoring/assets/{asset['id']}/summary").json()
    assert len(body["ports"]) == 2                                   # latest scan has both ports
    assert any(c["port"] == 80 for c in body["recent_changes"]), body["recent_changes"]


def test_summary_only_reflects_this_asset(client, make_asset, fake_nmap):
    mine = make_asset(name="mine", ip_address="10.0.0.5")
    make_asset(name="other", ip_address="10.0.0.6")
    _version_scan(fake_nmap, "10.0.0.6",
                  PORT.format(portid=3306, name="mysql", product="MySQL", version="8.0"))

    body = client.get(f"/monitoring/assets/{mine['id']}/summary").json()
    assert body["scanned"] is False                                 # the scan was of the other asset


def test_summary_requires_authentication(anon_client):
    assert anon_client.get("/monitoring/assets/any-id/summary").status_code == 401

"""Host-to-asset linking (ASSET-64).

Covers the matching rules (exact / ambiguous / no match / inactive), that links
survive an asset IP change, the candidate + link/unlink + create-from-host API,
permissions (assets:write), and audit logging. nmap is faked — no real scans.
"""
import pytest
from sqlalchemy import select

from app.assets.models import Asset, LifecycleStatus
from app.database import session_scope
from app.monitoring import scanner, service
from app.monitoring.models import MonitoredAsset

HOST_XML = '<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/></host></nmaprun>'


@pytest.fixture
def fake_nmap(monkeypatch):
    holder = {"xml": "<nmaprun></nmaprun>"}
    monkeypatch.setattr(scanner, "_run_nmap", lambda args: holder["xml"])
    return holder


def _discover(fake_nmap, ip):
    """Create a discovered host by running a (faked) discovery scan of `ip`."""
    fake_nmap["xml"] = HOST_XML.format(ip=ip)
    return service.run_discovery(ip)


def _host(ip):
    with session_scope() as session:
        h = session.scalar(select(MonitoredAsset).where(MonitoredAsset.ip == ip))
        return {"id": h.id, "managed_asset_id": h.managed_asset_id} if h else None


def _set(asset_id, **fields):
    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        for k, v in fields.items():
            setattr(asset, k, v)


# --- matching rules (auto-link on scan) -------------------------------------

def test_scan_auto_links_exact_active_match(client, make_asset, fake_nmap):
    asset = make_asset(name="web", ip_address="10.0.0.5")
    _discover(fake_nmap, "10.0.0.5")
    assert _host("10.0.0.5")["managed_asset_id"] == asset["id"]


def test_ambiguous_match_is_not_auto_linked(client, make_asset, fake_nmap):
    make_asset(name="a", ip_address="10.0.0.5")
    make_asset(name="b", ip_address="10.0.0.5")
    _discover(fake_nmap, "10.0.0.5")
    assert _host("10.0.0.5")["managed_asset_id"] is None
    entry = next(c for c in client.get("/monitoring/candidates").json() if c["ip"] == "10.0.0.5")
    assert entry["ambiguous"] is True and entry["suggested_asset_id"] is None


def test_no_match_leaves_host_unmanaged(client, make_asset, fake_nmap):
    make_asset(name="elsewhere", ip_address="10.0.0.9")
    _discover(fake_nmap, "10.0.0.5")
    assert _host("10.0.0.5")["managed_asset_id"] is None
    entry = next(c for c in client.get("/monitoring/candidates").json() if c["ip"] == "10.0.0.5")
    assert entry["suggested_asset_id"] is None and entry["ambiguous"] is False


def test_inactive_asset_is_not_matched(client, make_asset, fake_nmap):
    asset = make_asset(name="retired", ip_address="10.0.0.5")
    _set(asset["id"], status=LifecycleStatus.INACTIVE)
    _discover(fake_nmap, "10.0.0.5")
    assert _host("10.0.0.5")["managed_asset_id"] is None


def test_asset_ip_change_does_not_break_link(client, make_asset, fake_nmap):
    asset = make_asset(name="web", ip_address="10.0.0.5")
    _discover(fake_nmap, "10.0.0.5")
    assert _host("10.0.0.5")["managed_asset_id"] == asset["id"]
    _set(asset["id"], ip_address="10.0.0.99")                      # asset moves IP
    assert _host("10.0.0.5")["managed_asset_id"] == asset["id"]    # link is by id, intact


# --- manual link / unlink API + permissions ---------------------------------

def _make_asset_as(client_obj, name, ip):
    r = client_obj.post("/assets", json={"name": name, "asset_type": "server",
                                         "environment": "production", "criticality": "high",
                                         "ip_address": ip})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_manual_link_requires_assets_write(client_as, fake_nmap):
    _discover(fake_nmap, "10.0.0.7")
    host_id = _host("10.0.0.7")["id"]
    analyst = client_as("analyst")
    asset_id = _make_asset_as(analyst, "srv", "10.0.0.50")

    assert client_as("viewer").post(f"/monitoring/hosts/{host_id}/link",
                                    json={"asset_id": asset_id}).status_code == 403
    assert analyst.post(f"/monitoring/hosts/{host_id}/link",
                        json={"asset_id": asset_id}).status_code == 200
    assert _host("10.0.0.7")["managed_asset_id"] == asset_id

    assert analyst.post(f"/monitoring/hosts/{host_id}/unlink").status_code == 200
    assert _host("10.0.0.7")["managed_asset_id"] is None


def test_link_unknown_host_is_404(client, make_asset):
    asset = make_asset(name="x", ip_address="10.0.0.5")
    assert client.post("/monitoring/hosts/9999/link",
                       json={"asset_id": asset["id"]}).status_code == 404


def test_link_inactive_asset_is_400(client, make_asset, fake_nmap):
    asset = make_asset(name="x", ip_address="10.0.0.9")
    _set(asset["id"], status=LifecycleStatus.INACTIVE)
    _discover(fake_nmap, "10.0.0.6")
    host_id = _host("10.0.0.6")["id"]
    assert client.post(f"/monitoring/hosts/{host_id}/link",
                       json={"asset_id": asset["id"]}).status_code == 400


def test_create_asset_from_host(client, fake_nmap):
    _discover(fake_nmap, "10.0.0.8")
    host_id = _host("10.0.0.8")["id"]
    r = client.post(f"/monitoring/hosts/{host_id}/create-asset",
                    json={"name": "from-host", "asset_type": "server",
                          "environment": "production", "criticality": "medium",
                          "ip_address": "10.0.0.8"})
    assert r.status_code == 201, r.text
    asset_id = r.json()["asset_id"]
    assert _host("10.0.0.8")["managed_asset_id"] == asset_id
    assert client.get(f"/assets/{asset_id}").status_code == 200


# --- audit ------------------------------------------------------------------

def test_auto_link_is_audit_logged(client, make_asset, fake_nmap):
    make_asset(name="web", ip_address="10.0.0.5")
    _discover(fake_nmap, "10.0.0.5")
    events = client.get("/audit", params={"action": "monitoring.host_linked"}).json()["items"]
    assert events and events[0]["details"]["auto"] is True


def test_manual_unlink_is_audit_logged(client, make_asset, fake_nmap):
    make_asset(name="web", ip_address="10.0.0.5")
    _discover(fake_nmap, "10.0.0.5")
    host_id = _host("10.0.0.5")["id"]
    client.post(f"/monitoring/hosts/{host_id}/unlink")
    actions = {e["action"] for e in client.get("/audit").json()["items"]}
    assert "monitoring.host_unlinked" in actions

"""Asset Management API workflows."""
import uuid
from datetime import datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app import database
from app.assets.models import Asset, AssetTag


def _errors(response):
    return {err["loc"][-1]: err["msg"] for err in response.json()["detail"]}


# 1. create ----------------------------------------------------------------------

def test_create_valid_asset(client):
    body = {
        "name": "  web-prod-01  ", "asset_type": "web_application", "environment": "production",
        "criticality": "critical", "ip_address": "10.0.4.12", "hostname": "Web01.Corp.Example.",
        "owner": "Platform Team", "internet_facing": "yes",
        "description": "Customer portal", "tags": ["PCI", "dmz", "pci", " "],
    }
    r = client.post("/assets", json=body)
    assert r.status_code == 201
    a = r.json()
    assert uuid.UUID(a["id"]).version == 4
    assert a["name"] == "web-prod-01"
    assert a["hostname"] == "web01.corp.example"
    assert a["tags"] == ["dmz", "pci"]
    assert a["status"] == "active" and a["deactivated_at"] is None
    assert a["created_at"] == a["updated_at"]
    assert datetime.fromisoformat(a["created_at"]).tzinfo is not None


def test_create_defaults_and_empty_optional_fields(make_asset):
    a = make_asset(ip_address="", hostname="   ", owner="", description="", tags=[])
    assert a["ip_address"] is None and a["hostname"] is None and a["owner"] is None
    assert a["description"] is None and a["tags"] == []
    assert a["internet_facing"] == "unknown"


def test_asset_ids_do_not_depend_on_name_or_ip(make_asset):
    a = make_asset(name="db", ip_address="10.0.0.1")
    b = make_asset(name="db", ip_address="10.0.0.1")       # names and IPs are not unique keys
    assert a["id"] != b["id"]


def test_ipv6_is_normalized(make_asset):
    assert make_asset(ip_address="2001:0db8:0000::0001")["ip_address"] == "2001:db8::1"


# 2. reject invalid ----------------------------------------------------------------

@pytest.mark.parametrize("override, field", [
    ({"name": ""}, "name"),
    ({"name": "   "}, "name"),
    ({"asset_type": "mainframe"}, "asset_type"),
    ({"environment": "prod"}, "environment"),
    ({"criticality": "extreme"}, "criticality"),
    ({"internet_facing": "maybe"}, "internet_facing"),
    ({"ip_address": "999.1.1.1"}, "ip_address"),
    ({"ip_address": "10.0.0.1; DROP TABLE"}, "ip_address"),
    ({"hostname": "bad host!"}, "hostname"),
    ({"tags": ["<script>"]}, "tags"),
    ({"tags": [f"t{i}" for i in range(21)]}, "tags"),
    ({"status": "inactive"}, "status"),         # lifecycle starts as active; not settable on create
    ({"id": "00000000-0000-4000-8000-000000000000"}, "id"),
])
def test_reject_invalid_asset(client, override, field):
    body = {"name": "x", "asset_type": "server", "environment": "test", "criticality": "low", **override}
    r = client.post("/assets", json=body)
    assert r.status_code == 422
    assert field in _errors(r)


def test_missing_required_fields_are_reported(client):
    r = client.post("/assets", json={})
    assert r.status_code == 422
    assert set(_errors(r)) == {"name", "asset_type", "environment", "criticality"}


def test_error_messages_are_understandable(client):
    r = client.post("/assets", json={"name": "x", "asset_type": "server", "environment": "test",
                                     "criticality": "low", "ip_address": "300.0.0.1"})
    assert "valid IPv4 or IPv6 address" in _errors(r)["ip_address"]
    r = client.post("/assets", json={"name": "x", "asset_type": "server", "environment": "prod",
                                     "criticality": "low"})
    assert "'production'" in _errors(r)["environment"]      # lists the allowed values


# 3./4./5. list, retrieve, 404 ----------------------------------------------------------

def test_list_assets(client, make_asset):
    assert client.get("/assets").json() == {"items": [], "total": 0, "limit": 100, "offset": 0}
    make_asset(name="a")
    make_asset(name="b")
    data = client.get("/assets").json()
    assert data["total"] == 2
    assert [a["name"] for a in data["items"]] == ["b", "a"]          # most recently updated first
    assert [a["name"] for a in client.get("/assets?sort=name").json()["items"]] == ["a", "b"]
    paged = client.get("/assets?sort=name&limit=1&offset=1").json()
    assert paged["total"] == 2 and [a["name"] for a in paged["items"]] == ["b"]


def test_retrieve_asset(client, make_asset):
    a = make_asset(owner="SecOps")
    r = client.get(f"/assets/{a['id']}")
    assert r.status_code == 200 and r.json() == a
    assert client.get(f"/assets/{a['id'].upper()}").json()["id"] == a["id"]


@pytest.mark.parametrize("asset_id", [str(uuid.uuid4()), "not-a-uuid", "1"])
def test_unknown_asset_returns_404(client, asset_id):
    for method, path, body in (("get", "", None), ("patch", "", {"owner": "x"}),
                               ("post", "/deactivate", None), ("post", "/activate", None)):
        r = client.request(method.upper(), f"/assets/{asset_id}{path}", json=body)
        assert r.status_code == 404, (method, path)
        assert "not found" in r.json()["detail"]


# 6./7. update -------------------------------------------------------------------------

def test_update_asset_preserves_id_and_created_at(client, make_asset):
    a = make_asset(ip_address="10.0.0.1", tags=["dmz"])
    r = client.patch(f"/assets/{a['id']}", json={
        "name": "web-prod-01a", "ip_address": "10.0.0.2", "criticality": "critical",
        "owner": "Platform Team", "tags": ["dmz", "pci"]})
    assert r.status_code == 200
    u = r.json()
    assert u["id"] == a["id"]
    assert u["created_at"] == a["created_at"]
    assert u["updated_at"] > a["updated_at"]
    assert (u["name"], u["ip_address"], u["criticality"], u["owner"], u["tags"]) == \
        ("web-prod-01a", "10.0.0.2", "critical", "Platform Team", ["dmz", "pci"])
    assert u["asset_type"] == a["asset_type"]                         # omitted fields unchanged


def test_update_cannot_change_identifier_or_creation_time(client, make_asset):
    a = make_asset()
    for forbidden in ({"id": str(uuid.uuid4())}, {"created_at": "2000-01-01T00:00:00Z"}):
        r = client.patch(f"/assets/{a['id']}", json=forbidden)
        assert r.status_code == 422
    assert client.get(f"/assets/{a['id']}").json() == a


def test_update_clears_optional_fields_but_not_required_ones(client, make_asset):
    a = make_asset(owner="SecOps", ip_address="10.0.0.1", tags=["x"])
    u = client.patch(f"/assets/{a['id']}", json={"owner": None, "ip_address": "", "tags": []}).json()
    assert u["owner"] is None and u["ip_address"] is None and u["tags"] == []
    for field in ("name", "asset_type", "environment", "criticality", "status"):
        assert client.patch(f"/assets/{a['id']}", json={field: None}).status_code == 422
    assert client.patch(f"/assets/{a['id']}", json={"name": "  "}).status_code == 422


def test_noop_update_keeps_updated_at(client, make_asset):
    a = make_asset(owner="SecOps")
    u = client.patch(f"/assets/{a['id']}", json={"owner": "SecOps", "criticality": "high"}).json()
    assert u["updated_at"] == a["updated_at"]


# 8. deactivate --------------------------------------------------------------------------

def test_deactivate_keeps_the_record(client, make_asset):
    a = make_asset(tags=["pci"])
    r = client.post(f"/assets/{a['id']}/deactivate")
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "inactive" and d["deactivated_at"] is not None and d["id"] == a["id"]

    # Still stored and retrievable; hidden only when filtering for active assets.
    assert client.get(f"/assets/{a['id']}").json()["status"] == "inactive"
    assert client.get("/assets?status=active").json()["total"] == 0
    assert client.get("/assets?status=inactive").json()["total"] == 1
    with next(database.get_session()) as session:
        assert session.get(Asset, a["id"]) is not None
        assert session.scalars(select(AssetTag.tag)).all() == ["pci"]

    # There is no DELETE endpoint - records are never destroyed through the API.
    assert client.delete(f"/assets/{a['id']}").status_code == 405

    r = client.post(f"/assets/{a['id']}/activate").json()
    assert r["status"] == "active" and r["deactivated_at"] is None


def test_status_can_also_be_changed_via_update(client, make_asset):
    a = make_asset()
    u = client.patch(f"/assets/{a['id']}", json={"status": "inactive"}).json()
    assert u["status"] == "inactive" and u["deactivated_at"]
    # Editing other fields of an inactive asset does not move its deactivation time.
    u2 = client.patch(f"/assets/{a['id']}", json={"status": "inactive", "owner": "x"}).json()
    assert u2["deactivated_at"] == u["deactivated_at"]


# 9./10. search and filter -----------------------------------------------------------------

@pytest.fixture
def inventory(make_asset):
    make_asset(name="Web Portal", ip_address="203.0.113.10", hostname="portal.example.com",
               asset_type="web_application", environment="production", criticality="critical",
               internet_facing="yes", tags=["dmz"])
    make_asset(name="build-agent", ip_address="10.20.0.5", hostname="ci01.corp.example",
               asset_type="virtual_machine", environment="development", criticality="low",
               internet_facing="no")
    make_asset(name="hr-db", ip_address="10.30.0.7", asset_type="database",
               environment="production", criticality="high")


def _names(client, query):
    r = client.get(f"/assets?sort=name&{query}")
    assert r.status_code == 200, r.text
    return [a["name"] for a in r.json()["items"]]


@pytest.mark.parametrize("query, expected", [
    ("q=portal", ["Web Portal"]),               # name, case-insensitive
    ("q=WEB", ["Web Portal"]),
    ("q=10.20.0", ["build-agent"]),             # IP address
    ("q=corp.example", ["build-agent"]),        # hostname
    ("q=nothing-matches", []),
    ("q=%25", []),                              # LIKE wildcards are escaped
    ("q=_", []),
])
def test_search(client, inventory, query, expected):
    assert _names(client, query) == expected


@pytest.mark.parametrize("query, expected", [
    ("environment=production", ["hr-db", "Web Portal"]),
    ("criticality=critical", ["Web Portal"]),
    ("environment=production&criticality=high", ["hr-db"]),
    ("asset_type=virtual_machine", ["build-agent"]),
    ("internet_facing=unknown", ["hr-db"]),
    ("tag=DMZ", ["Web Portal"]),
    ("status=active", ["build-agent", "hr-db", "Web Portal"]),
    ("status=inactive", []),
])
def test_filter(client, inventory, query, expected):
    assert _names(client, query) == expected


def test_invalid_filter_values_are_rejected(client):
    assert client.get("/assets?environment=prod").status_code == 422
    assert client.get("/assets?limit=0").status_code == 422
    assert client.get("/assets?sort=random").status_code == 422


# misc ------------------------------------------------------------------------------------

def test_options_list_controlled_values(client):
    opts = client.get("/assets/options").json()
    assert [o["label"] for o in opts["asset_type"]] == [
        "Server", "Workstation", "Laptop", "Virtual Machine", "Container", "Network Device",
        "Database", "Web Application", "Cloud Resource", "Other"]
    assert [o["value"] for o in opts["environment"]] == ["development", "test", "staging", "production"]
    assert [o["label"] for o in opts["internet_facing"]] == ["Yes", "No", "Unknown"]


def test_database_errors_do_not_leak_details(client, make_asset, monkeypatch):
    from app.assets import service

    def broken(*args, **kwargs):
        raise OperationalError("SELECT secret FROM asset_inventory", {}, Exception("disk I/O error"))

    monkeypatch.setattr(service, "list_assets", broken)
    r = client.get("/assets")
    assert r.status_code == 500
    assert r.json() == {"detail": "A database error occurred. Please try again later."}


def test_web_ui_and_docs_are_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "Asset Management" in r.text
    assert client.get("/static/app.js").status_code == 200
    assert "/assets" in client.get("/openapi.json").json()["paths"]


def test_monitoring_module_still_available(client):
    assert client.get("/monitoring/scans").json() == []
    assert client.get("/health").json() == {"status": "ok"}

"""Cybermock demo inventory: valid, complete (incl. cloud), idempotent and audit-logged."""
from collections import Counter

from app import maintenance
from app.assets.schemas import AssetCreate
from app.demo import cybermock


def test_every_demo_asset_passes_api_validation():
    items = cybermock.inventory()
    for item in items:
        AssetCreate(**item)                                   # raises on invalid data
    assert len({i["name"] for i in items}) == len(items)      # unique names
    assert all(cybermock.DEMO_TAG in i["tags"] for i in items)


def test_inventory_matches_the_cybermock_documents():
    items = cybermock.inventory()
    types = Counter(i["asset_type"] for i in items)
    endpoints = types["laptop"] + types["workstation"]
    assert 38 <= endpoints <= 45                               # "~40 Windows laptops and desktops"
    names = {i["name"] for i in items}
    assert {"CM-DC01", "CM-FS01", "CM-HR01", "CM-SIEM01"} <= names
    assert {"cminsights544g9v", "labscripts45thai"} <= names   # storage accounts from the cloud audit


def test_cloud_infrastructure_is_included():
    cloud = [i for i in cybermock.inventory() if "cloud" in i["tags"]]
    assert len(cloud) >= 15
    azure = [i for i in cloud if "provider:azure" in i["tags"]]
    assert {i["asset_type"] for i in azure} >= {"cloud_resource", "web_application", "database", "container",
                                                "virtual_machine", "network_device"}
    for item in azure:
        if item["name"].startswith("Entra ID"):
            continue
        tag_keys = {t.split(":", 1)[0] for t in item["tags"] if ":" in t}
        assert {"subscription", "rg", "region", "azure"} <= tag_keys, item["name"]
    exposed = [i["name"] for i in cloud if i["internet_facing"] == "yes"]
    assert "app-cm-customerportal-prod" in exposed and "cminsights544g9v" in exposed


def test_only_private_or_documentation_addresses():
    import ipaddress
    doc_ranges = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for item in cybermock.inventory():
        if item.get("ip_address"):
            ip = ipaddress.ip_address(item["ip_address"])
            assert ip.is_private or any(ip in n for n in doc_ranges), item["name"]


def test_seed_demo_is_idempotent_and_audited(client):
    first = maintenance.seed_demo()
    total = len(cybermock.inventory())
    assert first == {"dataset": "cybermock", "created": total, "skipped": 0}
    assert maintenance.seed_demo() == {"dataset": "cybermock", "created": 0, "skipped": total}

    assert client.get("/assets?limit=500").json()["total"] == total            # no status filter = all
    inactive = client.get("/assets?status=inactive").json()["items"]
    assert [a["name"] for a in inactive] == ["CM-LT-INC2031"]
    assert client.get("/assets?tag=provider:azure&limit=500").json()["total"] >= 15
    assert client.get("/assets?q=cminsights").json()["items"][0]["internet_facing"] == "yes"

    created = client.get("/audit", params={"action": "asset.create", "limit": 1}).json()
    assert created["total"] == total and created["items"][0]["actor_username"].startswith("cli:")


def test_seed_demo_cli(client, capsys):
    assert maintenance.main(["seed-demo"]) == 0
    assert "assets created" in capsys.readouterr().out

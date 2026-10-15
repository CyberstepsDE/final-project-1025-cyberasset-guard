"""Audit log: completeness, content, integrity and access."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import database
from app.audit import service as audit_service
from app.monitoring import scanner
from conftest import TEST_PASSWORD

ROOT = Path(__file__).resolve().parent.parent
ASSET = {"name": "web-01", "asset_type": "server", "environment": "production", "criticality": "high"}


def events(client, **params) -> list[dict]:
    r = client.get("/audit", params={"limit": 500, **params})
    assert r.status_code == 200, r.text
    return r.json()["items"]


def last(client, action: str) -> dict:
    found = events(client, action=action)
    assert found, f"no audit event {action}"
    return found[0]


def test_login_events(client, make_user, monkeypatch):
    from app import config
    monkeypatch.setattr(config, "LOGIN_MAX_FAILURES", 2)
    make_user("eve")
    c = TestClient(client.app)
    c.post("/auth/login", json={"username": "eve", "password": "wrong-password-1"})
    c.post("/auth/login", json={"username": "eve", "password": "wrong-password-2"})
    c.post("/auth/login", json={"username": "ghost", "password": "whatever-password"})

    logins = events(client, action="auth.login")
    ok = [e for e in logins if e["outcome"] == "success"]
    assert ok and ok[-1]["actor_username"] == "admin" and ok[-1]["ip_address"] == "testclient"
    failures = [e for e in logins if e["outcome"] == "failure"]
    reasons = sorted(e["details"]["reason"] for e in failures)
    assert reasons == ["unknown user", "wrong password", "wrong password"]
    ghost = next(e for e in failures if e["details"]["reason"] == "unknown user")
    assert ghost["actor_username"] == "ghost" and ghost["actor_user_id"] is None

    lockout = last(client, "auth.lockout")
    assert lockout["target_label"] == "eve" and lockout["details"] == {"failures": 2, "minutes": 15}

    c.post("/auth/login", json={"username": "eve", "password": TEST_PASSWORD})
    locked = [e for e in events(client, action="auth.login", outcome="denied")]
    assert locked[0]["details"]["reason"] == "account locked"


def test_logout_and_password_events(client_as, client):
    analyst = client_as("analyst")
    analyst.post("/auth/password", json={"current_password": "nope-nope-nope", "new_password": "fresh-password-1"})
    analyst.post("/auth/password", json={"current_password": TEST_PASSWORD, "new_password": "fresh-password-1"})
    analyst.post("/auth/logout")
    changes = events(client, action="auth.password_change")
    assert [e["outcome"] for e in changes] == ["success", "failure"]
    assert last(client, "auth.logout")["actor_username"] == "analyst-user"


def test_asset_changes_are_recorded_with_diff(client):
    asset = client.post("/assets", json={**ASSET, "tags": ["pci"]}).json()
    created = last(client, "asset.create")
    assert created["target_id"] == asset["id"] and created["target_label"] == "web-01"
    assert created["details"]["values"]["criticality"] == "high"
    assert created["details"]["values"]["tags"] == ["pci"]

    client.patch(f"/assets/{asset['id']}", json={"criticality": "critical", "owner": "SecOps", "tags": []})
    updated = last(client, "asset.update")
    assert updated["details"]["changes"] == {
        "criticality": {"from": "high", "to": "critical"},
        "owner": {"from": None, "to": "SecOps"},
        "tags": {"from": ["pci"], "to": []},
    }
    client.patch(f"/assets/{asset['id']}", json={"owner": "SecOps"})          # no-op: nothing logged
    assert len(events(client, action="asset.update")) == 1

    client.post(f"/assets/{asset['id']}/deactivate")
    client.post(f"/assets/{asset['id']}/activate")
    assert last(client, "asset.deactivate")["details"]["changes"]["status"] == {"from": "active", "to": "inactive"}
    assert last(client, "asset.activate")["details"]["changes"]["status"] == {"from": "inactive", "to": "active"}

    history = events(client, target_type="asset", target_id=asset["id"])
    assert [e["action"] for e in history] == ["asset.activate", "asset.deactivate", "asset.update", "asset.create"]


def test_long_values_are_truncated(client):
    client.post("/assets", json={**ASSET, "description": "x" * 2000})
    stored = last(client, "asset.create")["details"]["values"]["description"]
    assert len(stored) == audit_service.MAX_VALUE_LENGTH + 1 and stored.endswith("…")


def test_change_and_audit_entry_are_atomic(client, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("audit storage unavailable")
    monkeypatch.setattr(audit_service, "record", broken)
    c = TestClient(client.app, raise_server_exceptions=False, cookies=client.cookies)
    assert c.post("/assets", json=ASSET).status_code == 500
    monkeypatch.undo()
    assert client.get("/assets").json()["total"] == 0                          # no unaudited change


def test_access_denied_is_recorded(client, client_as):
    viewer = client_as("viewer")
    viewer.post("/assets", json=ASSET)
    viewer.get("/audit")
    denied = events(client, action="access.denied")
    assert {(e["details"]["method"], e["details"]["path"], e["details"]["permission"]) for e in denied} == {
        ("POST", "/assets", "assets:write"), ("GET", "/audit", "audit:read")}
    assert all(e["actor_username"] == "viewer-user" and e["outcome"] == "denied" for e in denied)


def test_csrf_rejection_is_recorded(client):
    client.post("/assets", json=ASSET, headers={"Origin": "https://evil.example"})
    e = last(client, "access.csrf_rejected")
    assert e["details"]["origin"] == "https://evil.example" and e["outcome"] == "denied"


def test_user_management_events_never_contain_passwords(client):
    uid = client.post("/users", json={"username": "carol", "role": "viewer",
                                      "password": "c4-secret-pass!"}).json()["id"]
    client.patch(f"/users/{uid}", json={"role": "analyst"})
    client.patch(f"/users/{uid}", json={"is_active": False})
    client.patch(f"/users/{uid}", json={"is_active": True})
    client.post(f"/users/{uid}/password", json={"new_password": "c4-new-secret!!"})

    actions = [e["action"] for e in events(client, target_type="user", target_id=uid)]
    assert actions == ["user.password_reset", "user.enable", "user.disable", "user.role_change", "user.create"]
    assert last(client, "user.role_change")["details"]["changes"]["role"] == {"from": "viewer", "to": "analyst"}

    with database.get_engine().connect() as conn:
        dump = json.dumps([list(r) for r in conn.execute(text("SELECT * FROM audit_events"))], default=str)
    assert "c4-secret-pass!" not in dump and "c4-new-secret!!" not in dump and TEST_PASSWORD not in dump


def test_sensitive_keys_are_redacted():
    cleaned = audit_service._clean({"password": "p", "nested": {"token": "t", "ok": 1}})
    assert cleaned == {"password": "[redacted]", "nested": {"token": "[redacted]", "ok": 1}}


def test_monitoring_actions_are_recorded(client, monkeypatch):
    monkeypatch.setattr(scanner, "discover", lambda target: scanner.ScanResult(
        scan_type="discovery", target=target, args="nmap -sn (fake)", hosts=[]))
    assert client.post("/monitoring/discover", json={"target": "127.0.0.1"}).status_code == 200
    client.post("/monitoring/schedules", json={"scan_type": "bogus", "target": "x", "interval_seconds": 60})
    discover = last(client, "monitoring.discover")
    assert discover["outcome"] == "success" and discover["details"]["status"] == 200
    assert last(client, "monitoring.schedule_create")["outcome"] == "failure"


def test_audit_log_is_append_only(client):
    client.post("/assets", json=ASSET)
    with database.get_engine().connect() as conn:
        for statement in ("UPDATE audit_events SET action = 'tampered'", "DELETE FROM audit_events"):
            with pytest.raises(Exception, match="append-only"):
                conn.execute(text(statement))
            conn.rollback()
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert client.request(method, "/audit").status_code == 405


def test_filters_and_paging(client):
    for i in range(3):
        client.post("/assets", json={**ASSET, "name": f"a{i}"})
    assert {e["action"] for e in events(client, action="auth.*")} == {"auth.login"}
    assert len(events(client, action="asset.create")) == 3
    assert events(client, actor="ADMIN") and not events(client, actor="nobody")
    page = client.get("/audit", params={"action": "asset.create", "limit": 2, "offset": 2}).json()
    assert page["total"] == 3 and len(page["items"]) == 1 and page["items"][0]["target_label"] == "a0"
    assert events(client, since="2000-01-01T00:00:00") and not events(client, until="2000-01-01T00:00:00Z")
    assert client.get("/audit", params={"outcome": "maybe"}).status_code == 422


def test_cli_actions_are_attributed_to_the_os_user(tmp_path):
    env_db = tmp_path / "cli.db"
    import os
    env = {**os.environ, "CAG_DB_PATH": str(env_db)}
    result = subprocess.run([sys.executable, "-m", "app.maintenance", "create-user", "root-admin",
                             "--role", "admin", "--password-stdin"], cwd=ROOT, env=env,
                            input="cli-created-password\n", capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    database.configure(env_db)
    with database.get_engine().connect() as conn:
        actor, action = conn.execute(text("SELECT actor_username, action FROM audit_events")).one()
    assert action == "user.create" and actor.startswith("cli:")

"""Authentication, sessions, role-based access control and user management."""
from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app import config, database
from app.auth import passwords
from app.auth.dependencies import COOKIE_NAME
from app.auth.models import User, UserSession
from app.database import utcnow
from app.monitoring import scanner
from conftest import TEST_PASSWORD, login

ASSET = {"name": "srv", "asset_type": "server", "environment": "test", "criticality": "low"}


def _session():
    return next(database.get_session())


# --- public vs. protected ----------------------------------------------------------------------

@pytest.mark.parametrize("method, path", [
    ("GET", "/assets"), ("GET", "/assets/options"), ("POST", "/assets"), ("GET", "/monitoring/scans"),
    ("POST", "/monitoring/discover"), ("GET", "/users"), ("GET", "/audit"), ("GET", "/auth/me"),
    ("POST", "/auth/password"),
])
def test_protected_endpoints_require_login(anon_client, method, path):
    r = anon_client.request(method, path, json={})
    assert r.status_code == 401
    assert r.json() == {"detail": "Authentication required"}


@pytest.mark.parametrize("path", ["/", "/static/app.js", "/health", "/health/live", "/health/ready",
                                  "/docs", "/openapi.json", "/auth/status"])
def test_public_endpoints(anon_client, path):
    assert anon_client.get(path).status_code == 200


def test_setup_status(anon_client, make_user):
    assert anon_client.get("/auth/status").json() == {"setup_required": True}
    make_user("first-admin", "admin")
    assert anon_client.get("/auth/status").json() == {"setup_required": False}


# --- login / logout / sessions -------------------------------------------------------------------

def test_login_sets_secure_session_cookie(anon_client, make_user):
    make_user("Alice.Admin".lower(), "admin", display_name="Alice")
    r = login(anon_client, "  ALICE.admin ")                     # case-insensitive, trimmed
    me = r.json()
    assert me["username"] == "alice.admin" and me["role"] == "admin" and me["display_name"] == "Alice"
    assert "users:manage" in me["permissions"]

    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE_NAME}=")
    for attribute in ("HttpOnly", "SameSite=strict", "Path=/"):
        assert attribute.lower() in cookie.lower()
    assert "secure" not in cookie.lower()                         # CAG_COOKIE_SECURE defaults to off

    token = anon_client.cookies[COOKIE_NAME]
    with _session() as s:
        stored = s.scalars(select(UserSession.token_hash)).all()
    assert stored == [hashlib.sha256(token.encode()).hexdigest()]  # only the hash is stored
    assert anon_client.get("/auth/me").json()["username"] == "alice.admin"


def test_secure_cookie_flag_is_configurable(anon_client, make_user, monkeypatch):
    monkeypatch.setattr(config, "COOKIE_SECURE", True)
    make_user("bob", "viewer")
    r = anon_client.post("/auth/login", json={"username": "bob", "password": TEST_PASSWORD})
    assert "secure" in r.headers["set-cookie"].lower()


@pytest.mark.parametrize("username, password", [
    ("viewer-1", "wrong-password-123"),          # wrong password
    ("nobody", TEST_PASSWORD),                   # unknown user
    ("disabled-1", TEST_PASSWORD),               # deactivated account
])
def test_failed_logins_are_indistinguishable(client, make_user, anon_client, username, password):
    make_user("viewer-1")
    disabled = make_user("disabled-1")
    client.patch(f"/users/{disabled}", json={"is_active": False})
    c = TestClient(client.app)
    r = c.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 401
    assert r.json() == {"detail": "Invalid username or password"}
    assert COOKIE_NAME not in c.cookies


def test_lockout_after_repeated_failures(client, make_user, monkeypatch):
    monkeypatch.setattr(config, "LOGIN_MAX_FAILURES", 3)
    make_user("target")
    c = TestClient(client.app)
    for _ in range(3):
        assert c.post("/auth/login", json={"username": "target", "password": "wrong-password-xx"}).status_code == 401
    # Locked: even the correct password is rejected, with the same generic message.
    r = c.post("/auth/login", json={"username": "target", "password": TEST_PASSWORD})
    assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password"
    users = {u["username"]: u for u in client.get("/users").json()}
    assert users["target"]["locked_until"] is not None

    # Lock expires ...
    with _session() as s:
        s.execute(update(User).where(User.username == "target").values(locked_until=utcnow() - timedelta(seconds=1)))
        s.commit()
    login(c, "target")


def test_admin_password_reset_unlocks(client, make_user, monkeypatch):
    monkeypatch.setattr(config, "LOGIN_MAX_FAILURES", 2)
    uid = make_user("locked-out")
    c = TestClient(client.app)
    for _ in range(2):
        c.post("/auth/login", json={"username": "locked-out", "password": "wrong-password-xx"})
    assert client.post(f"/users/{uid}/password", json={"new_password": "a-brand-new-passphrase"}).status_code == 204
    login(c, "locked-out", "a-brand-new-passphrase")


def test_logout_invalidates_session_server_side(client):
    token = client.cookies[COOKIE_NAME]
    assert client.post("/auth/logout").status_code == 204
    replay = TestClient(client.app, cookies={COOKIE_NAME: token})
    assert replay.get("/assets").status_code == 401            # stolen cookie is useless after logout
    assert client.post("/auth/logout").status_code == 204      # idempotent


@pytest.mark.parametrize("column", ["last_seen_at", "expires_at"])
def test_idle_and_absolute_session_expiry(client, column, monkeypatch):
    assert client.get("/assets").status_code == 200
    past = utcnow() - timedelta(minutes=config.SESSION_IDLE_MINUTES + 1)
    with _session() as s:
        s.execute(update(UserSession).values(**{column: past}))
        s.commit()
    assert client.get("/assets").status_code == 401
    with _session() as s:
        assert s.scalars(select(UserSession)).all() == []        # expired session removed


def test_invalid_or_forged_cookie(anon_client, make_user):
    make_user("xyz")
    forged = TestClient(anon_client.app, cookies={COOKIE_NAME: "forged-token"})
    assert forged.get("/assets").status_code == 401


# --- passwords ----------------------------------------------------------------------------------

def test_production_hash_parameters(monkeypatch):
    monkeypatch.setattr(passwords, "SCRYPT_N", 2 ** 15)          # undo the test speed-up
    hashed = passwords.hash_password("correct horse battery")
    scheme, n, r, p, salt, digest = hashed.split("$")
    assert (scheme, n, r, p) == ("scrypt", "32768", "8", "1")
    assert passwords.verify_password("correct horse battery", hashed)
    assert not passwords.verify_password("Correct horse battery", hashed)
    assert hashed != passwords.hash_password("correct horse battery")   # random salt
    assert not passwords.needs_rehash(hashed)


def test_verify_rejects_garbage_and_oversized_input():
    hashed = passwords.hash_password("long enough password")
    assert not passwords.verify_password("x" * 10_000, hashed)
    assert not passwords.verify_password("anything", "not-a-hash")


def test_weak_hashes_are_upgraded_on_login(anon_client, make_user, monkeypatch):
    make_user("legacy")                                            # hashed with N=2**10
    monkeypatch.setattr(passwords, "SCRYPT_N", 2 ** 11)
    login(anon_client, "legacy")
    with _session() as s:
        stored = s.scalar(select(User.password_hash).where(User.username == "legacy"))
    assert stored.split("$")[1] == str(2 ** 11)


@pytest.mark.parametrize("password, message", [
    ("short", "at least 12 characters"),
    ("x" * 129, "at most 128"),
    ("my-name-is-newuser!", "must not contain the username"),
])
def test_password_policy(client, password, message):
    r = client.post("/users", json={"username": "newuser", "password": password})
    assert r.status_code == 422 and message in str(r.json()["detail"])


def test_change_own_password(client_as):
    me = client_as("analyst")
    other = client_as("analyst")                                  # second session, same user
    r = me.post("/auth/password", json={"current_password": "wrong-current-pw", "new_password": "another-good-pass"})
    assert r.status_code == 400
    r = me.post("/auth/password", json={"current_password": TEST_PASSWORD, "new_password": "another-good-pass"})
    assert r.status_code == 204
    assert me.get("/auth/me").status_code == 200                  # current session kept
    assert other.get("/auth/me").status_code == 401               # other sessions signed out
    fresh = TestClient(me.app)
    assert fresh.post("/auth/login", json={"username": "analyst-user", "password": TEST_PASSWORD}).status_code == 401
    login(fresh, "analyst-user", "another-good-pass")


# --- RBAC -----------------------------------------------------------------------------------

@pytest.fixture
def fake_scanner(monkeypatch):
    def discover(target):
        return scanner.ScanResult(scan_type="discovery", target=target, args="nmap -sn (fake)",
                                  hosts=[scanner.HostResult(ip=target, state="up")])
    monkeypatch.setattr(scanner, "discover", discover)


MATRIX = [
    # method, path,                         viewer, analyst, admin
    ("GET", "/assets",                       200, 200, 200),
    ("GET", "/assets/options",               200, 200, 200),
    ("POST", "/assets",                      403, 201, 201),
    ("GET", "/monitoring/scans",             200, 200, 200),
    ("POST", "/monitoring/discover",         403, 200, 200),
    ("GET", "/findings",                     200, 200, 200),
    ("POST", "/correlation/run",             403, 202, 202),
    ("GET", "/users",                        403, 403, 200),
    ("POST", "/users",                       403, 403, 201),
    ("GET", "/audit",                        403, 403, 200),
    ("GET", "/auth/me",                      200, 200, 200),
]


@pytest.mark.parametrize("role, column", [("viewer", 2), ("analyst", 3), ("admin", 4)])
def test_permission_matrix(client_as, fake_scanner, role, column):
    c = client_as(role)
    bodies = {"/assets": ASSET, "/monitoring/discover": {"target": "127.0.0.1"},
              "/users": {"username": f"made-by-{role}", "password": "a-perfectly-fine-pw"}}
    for row in MATRIX:
        method, path, expected = row[0], row[1], row[column]
        r = c.request(method, path, json=bodies.get(path) if method == "POST" else None)
        assert r.status_code == expected, (role, method, path, r.text)
        if expected == 403:
            assert "Your role does not allow this action" in r.json()["detail"]


def test_viewer_cannot_change_assets(client, client_as):
    asset = client.post("/assets", json=ASSET).json()
    viewer = client_as("viewer")
    assert viewer.get(f"/assets/{asset['id']}").status_code == 200
    for method, path in (("PATCH", f"/assets/{asset['id']}"), ("POST", f"/assets/{asset['id']}/deactivate"),
                         ("POST", f"/assets/{asset['id']}/activate")):
        assert viewer.request(method, path, json={"owner": "x"}).status_code == 403
    assert client.get(f"/assets/{asset['id']}").json() == asset          # unchanged


def test_analyst_can_manage_assets(client_as):
    analyst = client_as("analyst")
    asset = analyst.post("/assets", json=ASSET).json()
    assert analyst.patch(f"/assets/{asset['id']}", json={"owner": "SecOps"}).status_code == 200
    assert analyst.post(f"/assets/{asset['id']}/deactivate").json()["status"] == "inactive"


# --- user management ---------------------------------------------------------------------------

def test_user_lifecycle(client):
    r = client.post("/users", json={"username": "Jane.Doe", "display_name": "Jane", "role": "analyst",
                                    "password": "jane-initial-pass"})
    assert r.status_code == 201
    jane = r.json()
    assert jane["username"] == "jane.doe" and jane["role"] == "analyst" and jane["is_active"]
    assert "password" not in jane and "password_hash" not in jane

    assert client.post("/users", json={"username": "jane.doe", "password": "jane-initial-pass"}).status_code == 409
    assert client.post("/users", json={"username": "x", "password": "jane-initial-pass"}).status_code == 422
    assert client.post("/users", json={"username": "bad name!", "password": "jane-initial-pass"}).status_code == 422
    assert client.post("/users", json={"username": "ok-name", "password": "jane-initial-pass",
                                       "role": "root"}).status_code == 422
    assert client.get("/users/does-not-exist").status_code == 404

    u = client.patch(f"/users/{jane['id']}", json={"display_name": "Jane D."}).json()
    assert u["display_name"] == "Jane D."
    assert client.patch(f"/users/{jane['id']}", json={"role": None}).status_code == 422


def test_role_change_and_disable_take_effect_immediately(client):
    uid = client.post("/users", json={"username": "worker", "role": "analyst",
                                      "password": "staff-pass-1234!"}).json()["id"]
    w = TestClient(client.app)
    login(w, "worker", "staff-pass-1234!")
    assert w.post("/assets", json=ASSET).status_code == 201

    client.patch(f"/users/{uid}", json={"role": "viewer"})
    assert w.get("/assets").status_code == 401                  # sessions ended on role change
    login(w, "worker", "staff-pass-1234!")
    assert w.post("/assets", json=ASSET).status_code == 403     # new role applies

    client.patch(f"/users/{uid}", json={"is_active": False})
    assert w.get("/assets").status_code == 401
    assert TestClient(client.app).post("/auth/login", json={"username": "worker",
                                                            "password": "staff-pass-1234!"}).status_code == 401
    client.patch(f"/users/{uid}", json={"is_active": True})
    login(w, "worker", "staff-pass-1234!")


def test_last_admin_is_protected(client):
    me = client.get("/auth/me").json()
    for change in ({"role": "analyst"}, {"is_active": False}):
        r = client.patch(f"/users/{me['id']}", json=change)
        assert r.status_code == 409 and "last active administrator" in r.json()["detail"]
    second = client.post("/users", json={"username": "admin2", "role": "admin",
                                         "password": "second-admin-pass"}).json()
    assert client.patch(f"/users/{second['id']}", json={"role": "viewer"}).status_code == 200
    client.patch(f"/users/{second['id']}", json={"role": "admin"})
    assert client.patch(f"/users/{me['id']}", json={"role": "analyst"}).status_code == 200


# --- CSRF / headers -------------------------------------------------------------------------------

@pytest.mark.parametrize("headers, expected", [
    ({"Origin": "https://evil.example"}, 403),
    ({"Origin": "null"}, 403),
    ({"Referer": "https://evil.example/page"}, 403),
    ({"Referer": "http://testserver.evil.example/"}, 403),
    ({"Origin": "http://testserver"}, 201),
    ({"Referer": "http://testserver/#/assets/new"}, 201),
    ({}, 201),                                                    # non-browser client
])
def test_cross_origin_writes_are_rejected(client, headers, expected):
    r = client.post("/assets", json=ASSET, headers=headers)
    assert r.status_code == expected
    if expected == 403:
        assert r.json() == {"detail": "Cross-origin request rejected"}


def test_login_csrf_is_rejected(anon_client, make_user):
    make_user("victim")
    r = anon_client.post("/auth/login", json={"username": "victim", "password": TEST_PASSWORD},
                         headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_trusted_origins(client, monkeypatch):
    monkeypatch.setattr(config, "TRUSTED_ORIGINS", ("https://cag.example.com",))
    assert client.post("/assets", json=ASSET, headers={"Origin": "https://cag.example.com"}).status_code == 201


def test_security_headers(client):
    r = client.get("/assets")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "content-security-policy" not in client.get("/docs").headers      # Swagger needs its CDN

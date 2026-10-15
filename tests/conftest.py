"""Test fixtures. Every test runs against its own temporary SQLite file and backup
directory, so the development database (cyberasset_guard.db) is never touched.

PostgreSQL mode: with CAG_TEST_DATABASE_URL set (a DISPOSABLE test database - every
test drops and recreates its public schema), the whole suite runs against that server
instead. Tests marked `sqlite_only` (file backups, SQLite pragmas ...) are skipped there.

Clients:
  anon_client       not logged in
  client            logged in as an administrator (most API tests)
  client_as(role)   a separate client logged in with the given role
"""
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app import config, database
from app.audit import service as audit
from app.auth import passwords
from app.auth import service as auth_service
from app.auth.permissions import Role

TEST_PASSWORD = "correct-horse-battery-staple"
TEST_DATABASE_URL = os.environ.get("CAG_TEST_DATABASE_URL", "").strip() or None


def pytest_configure(config):
    config.addinivalue_line("markers", "sqlite_only: test exercises SQLite-file behaviour (skipped on PostgreSQL)")


def pytest_collection_modifyitems(config, items):
    if TEST_DATABASE_URL:
        skip = pytest.mark.skip(reason="SQLite-specific; suite runs against CAG_TEST_DATABASE_URL")
        for item in items:
            if "sqlite_only" in item.keywords:
                item.add_marker(skip)


def _reset_postgres(url: str) -> None:
    engine = create_engine(database._normalise_url(url))
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    path = tmp_path / "data" / "test.db"
    path.parent.mkdir()
    monkeypatch.setattr(config, "DB_PATH", path)
    monkeypatch.setattr(config, "BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(config, "CORRELATION_AFTER_SCAN", False)   # no NVD calls from scan tests
    from app.correlation import jobs as correlation_jobs
    monkeypatch.setattr(correlation_jobs, "run_in_background", lambda func, *args: func(*args))
    if TEST_DATABASE_URL:
        _reset_postgres(TEST_DATABASE_URL)
        monkeypatch.setattr(config, "DATABASE_URL", database._normalise_url(TEST_DATABASE_URL))
        database.configure(TEST_DATABASE_URL)
    else:
        monkeypatch.setattr(config, "DATABASE_URL", None)
        database.configure(path)
    # Create schema with create_all (fast) instead of running Alembic per test;
    # the dedicated migration tests (tests/test_migrations.py) exercise Alembic.
    monkeypatch.setattr(database, "ensure_schema", database.init_models)
    yield path
    database.get_engine().dispose()


@pytest.fixture(autouse=True)
def fast_password_hashing(monkeypatch):
    """Low scrypt cost keeps the suite fast; test_auth checks the production parameters."""
    monkeypatch.setattr(passwords, "SCRYPT_N", 2 ** 10)


@pytest.fixture
def app():
    from app.main import app as fastapi_app
    return fastapi_app


@pytest.fixture
def anon_client(app):
    with TestClient(app) as c:                      # runs startup: creates the schema
        yield c


@pytest.fixture
def make_user(anon_client):
    def _make(username: str, role: str = "viewer", password: str = TEST_PASSWORD, **kwargs):
        with next(database.get_session()) as session:
            user = auth_service.create_user(session, audit.SYSTEM, username, password, Role(role),
                                            kwargs.get("display_name"))
            return user.id
    return _make


def login(c: TestClient, username: str, password: str = TEST_PASSWORD):
    r = c.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r


@pytest.fixture
def client(anon_client, make_user):
    make_user("admin", "admin")
    login(anon_client, "admin")
    return anon_client


@pytest.fixture
def client_as(app, anon_client, make_user):
    created: set[str] = set()

    def _as(role: str) -> TestClient:
        username = f"{role}-user"
        if username not in created:
            make_user(username, role)
            created.add(username)
        c = TestClient(app)                         # schema already exists; no second lifespan
        login(c, username)
        return c
    return _as


@pytest.fixture
def make_asset(client):
    def _make(**overrides):
        body = {"name": "web-prod-01", "asset_type": "server", "environment": "production",
                "criticality": "high", **overrides}
        response = client.post("/assets", json=body)
        assert response.status_code == 201, response.text
        return response.json()
    return _make

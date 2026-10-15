"""Database-server support (CAG_DATABASE_URL / PostgreSQL).

Tests marked `postgres_only` run when CAG_TEST_DATABASE_URL points to a disposable
PostgreSQL database (locally: a Docker container; CI: a service container).
"""
import pytest
from sqlalchemy import text

from app import config, database, maintenance
from conftest import TEST_DATABASE_URL, TEST_PASSWORD, login

postgres_only = pytest.mark.skipif(not TEST_DATABASE_URL, reason="needs CAG_TEST_DATABASE_URL (PostgreSQL)")


def test_password_is_masked_in_logs_and_reports():
    database.configure("postgresql://cag:s3cr3t-value@db.example.invalid:5432/cag")
    try:
        described = database.describe()
        assert "s3cr3t-value" not in described and "***" in described
        assert database.dialect() == "postgresql" and database.sqlite_path() is None
        assert database.get_engine().url.drivername == "postgresql+psycopg"     # normalised driver
    finally:
        database.get_engine().dispose()


def test_file_backups_are_refused_for_a_database_server(monkeypatch):
    monkeypatch.setattr(config, "DATABASE_URL", "postgresql+psycopg://u:p@db.example.invalid/x")
    for action in (lambda: maintenance.backup(), lambda: maintenance.restore("whatever.db")):
        with pytest.raises(maintenance.MaintenanceError, match="SQLite file only"):
            action()


def test_invalid_database_url_is_reported(tmp_path):
    import os
    import subprocess
    import sys
    result = subprocess.run([sys.executable, "-c", "import app.config"], capture_output=True, text=True,
                            env={**os.environ, "CAG_DATABASE_URL": "mysql://x"}, timeout=60)
    assert result.returncode != 0 and "CAG_DATABASE_URL must start with postgresql" in result.stderr


@postgres_only
def test_whole_application_runs_on_postgres(client):
    assert database.dialect() == "postgresql"
    asset = client.post("/assets", json={"name": "pg", "asset_type": "server", "environment": "test",
                                         "criticality": "low"}).json()
    assert client.get(f"/assets/{asset['id']}").json()["name"] == "pg"
    assert client.get("/health/ready").json()["status"] == "ready"


@postgres_only
def test_audit_log_cannot_be_truncated_on_postgres(client):
    with database.get_engine().connect() as conn:
        for statement in ("UPDATE audit_events SET action = 'x'", "DELETE FROM audit_events",
                          "TRUNCATE audit_events"):
            with pytest.raises(Exception, match="append-only"):
                conn.execute(text(statement))
            conn.rollback()


@postgres_only
def test_copy_sqlite_database_to_server(tmp_path, monkeypatch, app):
    from fastapi.testclient import TestClient

    from conftest import _reset_postgres

    # 1. A populated SQLite database (demo inventory, a user, monitoring data).
    sqlite_file = tmp_path / "source.db"
    monkeypatch.setattr(config, "DATABASE_URL", None)
    monkeypatch.setattr(config, "DB_PATH", sqlite_file)
    maintenance.create_user("migrated-admin", "admin", TEST_PASSWORD)
    seeded = maintenance.seed_demo()["created"]
    from app.monitoring.models import Scan
    with database.session_scope() as db:
        db.add(Scan(scan_type="discovery", target="10.0.0.1", status="completed",
                    started_at="2026-10-13T00:00:00"))
    database.get_engine().dispose()

    # 2. Copy into the empty PostgreSQL database.
    _reset_postgres(TEST_DATABASE_URL)
    monkeypatch.setattr(config, "DATABASE_URL", database._normalise_url(TEST_DATABASE_URL))
    result = maintenance.copy_to_server(sqlite_file)
    assert "***" in result["target"]
    assert result["copied"]["asset_inventory"] == seeded
    assert result["copied"]["users"] == 1 and result["copied"]["scans"] == 1
    assert result["copied"]["audit_events"] >= seeded

    # 3. Copying again is refused (target not empty).
    with pytest.raises(maintenance.MaintenanceError, match="not empty"):
        maintenance.copy_to_server(sqlite_file)

    # 4. The application works on the copy: login, data, new ids continue after the copied ones.
    with TestClient(app) as c:
        login(c, "migrated-admin")
        assert c.get("/assets?limit=500").json()["total"] == seeded
        assert c.post("/assets", json={"name": "after-copy", "asset_type": "server", "environment": "test",
                                       "criticality": "low"}).status_code == 201
    with database.session_scope() as db:
        new = Scan(scan_type="discovery", target="10.0.0.2", status="completed", started_at="2026-10-13T00:00:01")
        db.add(new)
        db.flush()
        assert new.id == 2

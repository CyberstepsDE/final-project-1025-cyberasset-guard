"""Alembic migration tests (ASSET-45).

Verifies the baseline:
  - `upgrade head` on an empty database == the create_all schema (sqlite_master),
  - an existing pre-migration database can be upgraded (stamped) without data loss
    and with the audit_events append-only triggers still enforced.

These call the real Alembic path (database.run_migrations) on their own temp
databases, independent of the conftest ensure_schema monkeypatch.
"""
import sqlite3

import pytest
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from app import database
from conftest import TEST_DATABASE_URL


def _schema(path, exclude=("alembic_version",)):
    """(type, name, sql) for every object in sqlite_master, minus bookkeeping."""
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
    finally:
        conn.close()
    return [r for r in rows if r[1] not in exclude]


def _head_revision():
    return ScriptDirectory.from_config(database._alembic_config("sqlite://")).get_current_head()


def _current_revision(url):
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return MigrationContext.configure(conn).get_current_revision()
    finally:
        engine.dispose()


def test_upgrade_empty_db_matches_create_all(tmp_path):
    alembic_db = tmp_path / "alembic.db"
    create_all_db = tmp_path / "create_all.db"

    database.run_migrations(f"sqlite:///{alembic_db}")

    database._register_all_models()
    engine = create_engine(f"sqlite:///{create_all_db}")
    database.Base.metadata.create_all(engine)
    engine.dispose()

    assert _schema(alembic_db) == _schema(create_all_db)          # identical schema
    assert _current_revision(f"sqlite:///{alembic_db}") == _head_revision()


def test_baseline_includes_audit_triggers(tmp_path):
    db = tmp_path / "a.db"
    database.run_migrations(f"sqlite:///{db}")
    triggers = {name for typ, name, _ in _schema(db) if typ == "trigger"}
    assert triggers == {"audit_events_no_update", "audit_events_no_delete"}


def _seed_pre_migration_db(path):
    """A database as it looked before Alembic: create_all schema + some rows, no alembic_version."""
    database._register_all_models()
    engine = create_engine(f"sqlite:///{path}")
    database.Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO scans (scan_type, target, status, started_at) "
                          "VALUES ('discovery', '10.0.0.5', 'completed', '2026-01-01T00:00:00+00:00')"))
        conn.execute(text("INSERT INTO audit_events (occurred_at, action, outcome) "
                          "VALUES ('2026-01-01 00:00:00', 'test.event', 'success')"))
    engine.dispose()


def test_upgrade_from_pre_migration_db_preserves_data_and_triggers(tmp_path):
    db = tmp_path / "pre.db"
    _seed_pre_migration_db(db)
    assert _current_revision(f"sqlite:///{db}") is None           # no version yet

    database.run_migrations(f"sqlite:///{db}")                    # adopt/stamp existing DB

    assert _current_revision(f"sqlite:///{db}") == _head_revision()

    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT target FROM scans").fetchone()[0] == "10.0.0.5"   # data intact
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
        conn.execute("PRAGMA foreign_keys=ON")
        # Append-only triggers must survive the migration.
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("UPDATE audit_events SET action = 'tampered'")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM audit_events")
    finally:
        conn.close()


def test_run_migrations_is_idempotent(tmp_path):
    url = f"sqlite:///{tmp_path / 'i.db'}"
    database.run_migrations(url)
    database.run_migrations(url)                                  # no error, still at head
    assert _current_revision(url) == _head_revision()


@pytest.mark.skipif(not TEST_DATABASE_URL, reason="needs CAG_TEST_DATABASE_URL (PostgreSQL)")
def test_migrations_on_postgres():
    """Alembic runs on the configured server (password never in a config string),
    creates every table and the append-only triggers, and is idempotent."""
    database.run_migrations()
    database.run_migrations()
    engine = database.get_engine()
    assert _current_revision(engine.url.render_as_string(hide_password=False)) == _head_revision()
    with engine.connect() as conn:
        tables = set(conn.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'")).scalars())
        triggers = set(conn.execute(text(
            "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal")).scalars())
    database._register_all_models()
    assert set(database.Base.metadata.tables) | {"alembic_version"} == tables
    assert {"audit_events_no_update_delete", "audit_events_no_truncate"} <= triggers


def test_upgrade_from_0002_adds_risk_tables_matching_the_models(tmp_path):
    """A database migrated before the Risk engine existed (at 0002, no risk tables)
    gets them from 0003 - with exactly the columns the models define."""
    from alembic.autogenerate import compare_metadata

    url = f"sqlite:///{tmp_path / 'r.db'}"
    database.run_migrations(url)
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE finding_risk"))
        conn.execute(text("DROP TABLE asset_risk"))
        conn.execute(text("UPDATE alembic_version SET version_num = '0002_host_managed_asset'"))

    database.run_migrations(url)

    assert _current_revision(url) == _head_revision()
    database._register_all_models()
    with engine.connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn), database.Base.metadata)
    engine.dispose()
    assert [d for d in diffs if "risk" in repr(d)] == []


def test_upgrade_from_0003_adds_risk_history_matching_the_model(tmp_path):
    """A database at 0003 (risk tables, no history yet) gets asset_risk_history from 0004 -
    with exactly the columns and index the model defines."""
    from alembic.autogenerate import compare_metadata

    url = f"sqlite:///{tmp_path / 'h.db'}"
    database.run_migrations(url)
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE asset_risk_history"))
        conn.execute(text("UPDATE alembic_version SET version_num = '0003_risk_tables'"))

    database.run_migrations(url)

    assert _current_revision(url) == _head_revision()
    database._register_all_models()
    with engine.connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn), database.Base.metadata)
    engine.dispose()
    assert [d for d in diffs if "asset_risk_history" in repr(d)] == []


def test_upgrade_from_0004_adds_dashboard_schema_and_downgrade_removes_it(tmp_path):
    """0005: security_snapshots + correlation_runs.scope on a database at 0004, keeping its rows."""
    from alembic.autogenerate import compare_metadata

    from alembic import command

    url = f"sqlite:///{tmp_path / 'd.db'}"
    database.run_migrations(url)
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE security_snapshots"))
        conn.execute(text("ALTER TABLE correlation_runs DROP COLUMN scope"))
        conn.execute(text("INSERT INTO correlation_runs (trigger, status, started_at, assets_processed, "
                          "findings_opened, findings_reopened, findings_closed, unmapped_software, warnings) "
                          "VALUES ('scheduled', 'success', '2026-01-01 00:00:00', 1, 0, 0, 0, '', '')"))
        conn.execute(text("UPDATE alembic_version SET version_num = '0004_risk_history'"))

    database.run_migrations(url)

    assert _current_revision(url) == _head_revision()
    database._register_all_models()
    with engine.connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn), database.Base.metadata)
        assert [d for d in diffs if "security_snapshots" in repr(d) or "scope" in repr(d)] == []
        assert conn.execute(text("SELECT count(*) FROM correlation_runs")).scalar() == 1

    with engine.begin() as conn:                                  # like run_migrations: our connection
        cfg = database._alembic_config()
        cfg.attributes["connection"] = conn
        command.downgrade(cfg, "0004_risk_history")
    with engine.connect() as conn:
        tables = {r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'"))}
        columns = {r[1] for r in conn.execute(text("PRAGMA table_info(correlation_runs)"))}
        assert conn.execute(text("SELECT count(*) FROM correlation_runs")).scalar() == 1
    engine.dispose()
    assert "security_snapshots" not in tables and "scope" not in columns


def test_upgrade_from_0005_adds_jira_tickets_matching_the_model(tmp_path):
    """A database at 0005 gets jira_tickets from 0006 - with exactly the model's columns,
    the UNIQUE(finding_id) idempotency constraint and the state index."""
    from alembic.autogenerate import compare_metadata

    url = f"sqlite:///{tmp_path / 'j.db'}"
    database.run_migrations(url)
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE jira_tickets"))
        conn.execute(text("UPDATE alembic_version SET version_num = '0005_dashboard'"))

    database.run_migrations(url)

    assert _current_revision(url) == _head_revision()
    database._register_all_models()
    with engine.connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn), database.Base.metadata)
        uniques = {tuple(u["column_names"]) for u in inspect(conn).get_unique_constraints("jira_tickets")}
    engine.dispose()
    assert [d for d in diffs if "jira_tickets" in repr(d)] == []
    assert ("finding_id",) in uniques and ("label",) in uniques

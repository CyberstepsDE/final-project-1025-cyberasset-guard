"""Alembic environment.

target_metadata is the application's Base.metadata, so autogenerate sees every
model. The baseline revision creates the schema via create_all (see the baseline
script), which also emits the audit_events append-only triggers.

Database resolution:
  - programmatic runs (app/database.run_migrations) pass an open connection of the
    application's engine via config.attributes["connection"] (SQLite pragmas and
    PostgreSQL credentials already in place; no password in a config string);
  - the `alembic` CLI uses the application's configured database - CAG_DATABASE_URL
    if set, else CAG_DB_PATH - not the placeholder in alembic.ini.

Logging is intentionally left to the application: this file does not call
logging.config.fileConfig, and alembic.ini has no logging sections.
"""
from __future__ import annotations

from alembic import context
from app import config as app_config
from app import database

# Register all models so target_metadata is complete.
database._register_all_models()
target_metadata = database.Base.metadata


def _configured_target():
    return app_config.DATABASE_URL or app_config.DB_PATH


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a DB connection (`alembic upgrade --sql`)."""
    target = _configured_target()
    context.configure(
        url=database._normalise_url(target) if isinstance(target, str) else f"sqlite:///{target}",
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,          # SQLite: future ALTERs via batch (copy-and-move)
    )
    with context.begin_transaction():
        context.run_migrations()


def _migrate(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,          # SQLite: future ALTERs via batch
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = context.config.attributes.get("connection")
    if connection is not None:
        _migrate(connection)
        return
    # `alembic` CLI: same engine setup as the application (SQLite foreign_keys /
    # busy_timeout via a connect event, psycopg driver for PostgreSQL).
    engine = database._build_engine(_configured_target())
    try:
        with engine.connect() as connection:
            _migrate(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

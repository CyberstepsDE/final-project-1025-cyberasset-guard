"""SQLAlchemy engine / session handling for the whole application.

One database for everything: the local SQLite file (CAG_DB_PATH, default) or a
shared PostgreSQL server (CAG_DATABASE_URL, e.g. Azure Database for PostgreSQL).
Every module - Asset Management, Auth, Audit, Monitoring, Correlation - uses the
ORM defined here; request handlers use the `get_session` dependency and
background/CLI code uses the `session_scope` context manager.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import DateTime, create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator

from . import config


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC timestamps on top of SQLite (which stores naive values)."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not allowed; use UTC")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect):
        return value.replace(tzinfo=UTC) if value is not None else None


def utcnow() -> datetime:
    return datetime.now(UTC)


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _on_connect(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys = ON")
    # Wait (instead of failing with "database is locked") while Monitoring's
    # scheduler threads or another request hold the write lock.
    cursor.execute("PRAGMA busy_timeout = 5000")
    cursor.close()


def _normalise_url(url: str) -> str:
    # psycopg (v3) is the installed driver; plain postgresql:// would pick psycopg2.
    return "postgresql+psycopg://" + url[len("postgresql://"):] if url.startswith("postgresql://") else url


def _build_engine(target: Path | str) -> Engine:
    """Engine for a SQLite file path or a database URL (SQLite pragmas applied on connect)."""
    if "://" in str(target):
        url = _normalise_url(str(target))
        if url.startswith("sqlite"):
            engine = create_engine(url, connect_args={"check_same_thread": False})
            event.listen(engine, "connect", _on_connect)
            return engine
        return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5, pool_recycle=1800)
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _on_connect)
    return engine


def configure(target: Path | str | None = None) -> Engine:
    """(Re)create the engine. Called on startup and by tests to use an isolated database.

    `target` is a SQLite file path or a database URL; default: CAG_DATABASE_URL, else CAG_DB_PATH.
    """
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    if target is None:
        target = config.DATABASE_URL or config.DB_PATH
    _engine = _build_engine(target)
    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def get_engine() -> Engine:
    return _engine if _engine is not None else configure()


def dialect() -> str:
    return get_engine().dialect.name                     # 'sqlite' | 'postgresql'


def describe() -> str:
    """Where the data lives, safe for logs (password masked)."""
    url = get_engine().url
    return (url.database or ":memory:") if url.drivername.startswith("sqlite") else url.render_as_string(hide_password=True)


def sqlite_path() -> Path | None:
    """Path of the SQLite file, or None when a database server is used."""
    url = get_engine().url
    return Path(url.database) if url.drivername.startswith("sqlite") and url.database else None


def _register_all_models() -> None:
    """Import every model module so all tables are registered on Base.metadata."""
    from .assets import models as _assets  # noqa: F401
    from .audit import models as _audit  # noqa: F401
    from .auth import models as _auth  # noqa: F401
    from .correlation import models as _correlation  # noqa: F401
    from .dashboard import models as _dashboard  # noqa: F401
    from .monitoring import models as _monitoring  # noqa: F401
    from .risk import models as _risk  # noqa: F401
    from .ticketing import models as _ticketing  # noqa: F401


def init_models() -> None:
    """Create ORM tables that do not exist yet (idempotent, non-destructive).

    This is the schema created by `create_all`; the Alembic baseline revision
    delegates to it, so `alembic upgrade head` on an empty database produces an
    identical schema. Production startup uses `ensure_schema()` (Alembic); tests
    call this directly for speed.
    """
    _register_all_models()
    Base.metadata.create_all(get_engine())


REQUIRED_TABLES = ("asset_inventory", "asset_tags", "users", "user_sessions", "audit_events")


def check_ready() -> bool:
    """Readiness: the database answers and the schema exists. Never raises."""
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
            existing = set(inspect(conn).get_table_names())
        return all(t in existing for t in REQUIRED_TABLES)
    except Exception:  # noqa: BLE001 - any failure simply means "not ready"
        return False


def get_session() -> Iterator[Session]:
    """FastAPI dependency: one session per request, always closed."""
    get_engine()
    assert _session_factory is not None  # noqa: S101  # get_engine() initialises the factory above
    session = _session_factory()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session for non-request code (scheduler threads, CLI, services):
    commits on success, rolls back on error, always closes. Replaces the former
    sqlite3 get_conn() helper (app/db.py), so Monitoring uses the ORM as well."""
    get_engine()
    assert _session_factory is not None  # noqa: S101  # get_engine() initialises the factory above
    session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# --- schema migrations (Alembic) --------------------------------------------

def _alembic_config(url: str | None = None):
    """Alembic Config for this project's migrations. The application passes an open
    connection (see run_migrations) instead of a URL, so database passwords never
    end up in a config string; `url` is only for callers that need a script view."""
    from alembic.config import Config
    cfg = Config(str(config.BASE_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(config.BASE_DIR / "alembic"))
    if url:
        cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def run_migrations(target: Path | str | None = None) -> None:
    """Upgrade the database to the latest Alembic revision (head).

    `target` (SQLite path or URL) defaults to the configured engine's database. Safe
    on an empty database (creates the full schema) and on a pre-migration database
    (the baseline is create-if-not-exists, so it only adds the alembic_version
    bookkeeping - i.e. it stamps the existing schema without touching data). Works
    the same on SQLite and PostgreSQL: Alembic runs on a connection of our engine."""
    from alembic import command
    engine = get_engine() if target is None else _build_engine(target)
    try:
        with engine.begin() as connection:
            cfg = _alembic_config()
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "head")
    finally:
        if target is not None:
            engine.dispose()


def ensure_schema() -> None:
    """Production schema bootstrap: bring the database up to the latest migration.

    Tests monkeypatch this to `init_models` (plain create_all) for speed - see
    tests/conftest.py."""
    run_migrations()

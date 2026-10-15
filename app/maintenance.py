"""Operational commands: configuration check, database init, backup and restore.

    python -m app.maintenance check
    python -m app.maintenance init-db
    python -m app.maintenance backup [--output-dir DIR]
    python -m app.maintenance verify BACKUP_FILE
    python -m app.maintenance restore BACKUP_FILE --target PATH [--force]
    python -m app.maintenance create-user USERNAME --role admin [--password-stdin]
    python -m app.maintenance reset-password USERNAME [--password-stdin]
    python -m app.maintenance list-users
    python -m app.maintenance seed-demo [--dataset cybermock]
    python -m app.maintenance copy-to-server cyberasset_guard.db   (target: CAG_DATABASE_URL)

Backups use SQLite's online backup API (sqlite3.Connection.backup), which
produces a consistent snapshot even while the application is running -
unlike copying the live file, which can capture a half-written transaction.
"""
from __future__ import annotations

import argparse
import getpass
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import config

REQUIRED_TABLES = ("asset_inventory", "asset_tags")


class MaintenanceError(RuntimeError):
    pass


@dataclass
class BackupInfo:
    path: Path
    integrity: str
    assets: int
    tables: list[str]


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _same_file(a: Path, b: Path) -> bool:
    return a.resolve() == b.resolve()


def inspect_database(path: Path) -> BackupInfo:
    """Open read-only and check integrity + the Asset Management schema."""
    if not path.is_file():
        raise MaintenanceError(f"{path} does not exist")
    try:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            tables = sorted(r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"))
            assets = (conn.execute("SELECT COUNT(*) FROM asset_inventory").fetchone()[0]
                      if "asset_inventory" in tables else 0)
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        raise MaintenanceError(f"{path} is not a readable SQLite database: {exc}") from None
    return BackupInfo(path=path, integrity=integrity, assets=assets, tables=tables)


def verify_backup(path: Path) -> BackupInfo:
    info = inspect_database(path)
    if info.integrity != "ok":
        raise MaintenanceError(f"integrity check failed for {path}: {info.integrity}")
    missing = [t for t in REQUIRED_TABLES if t not in info.tables]
    if missing:
        raise MaintenanceError(f"{path} is not a CyberAsset Guard database (missing {missing})")
    return info


def _copy_sqlite(source: Path, target: Path) -> None:
    src = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()


def backup(db_path: Path | None = None, output_dir: Path | None = None) -> BackupInfo:
    """Write a consistent, verified snapshot to output_dir/cyberasset_guard-<UTC>.db."""
    if db_path is None:
        _require_sqlite("backup")
    db_path = Path(db_path or config.DB_PATH)
    output_dir = Path(output_dir or config.BACKUP_DIR)
    if not db_path.is_file():
        raise MaintenanceError(f"database {db_path} does not exist - nothing to back up")
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{db_path.stem}-{_timestamp()}.db"
    if target.exists() or _same_file(target, db_path):
        raise MaintenanceError(f"refusing to overwrite {target}")
    partial = target.with_suffix(".db.partial")
    _copy_sqlite(db_path, partial)
    try:
        info = verify_backup(partial)
    except MaintenanceError:
        partial.unlink(missing_ok=True)
        raise
    partial.rename(target)
    info.path = target
    return info


def prune_backups(output_dir: Path | None = None, keep_daily: int | None = None,
                  keep_weekly: int | None = None, stem: str | None = None,
                  now: datetime | None = None) -> dict:
    """Retention: keep the newest backup of each of the last `keep_daily` days and of each of the
    last `keep_weekly` ISO weeks (the newest backup is always kept).

    Only regular files named exactly like `backup()` writes them for this database
    (<db stem>-<UTC timestamp>.db) are considered. Other files, restore safety copies,
    unparseable names and timestamps in the future are never deleted.
    """
    output_dir = Path(output_dir or config.BACKUP_DIR)
    keep_daily = config.BACKUP_KEEP_DAILY if keep_daily is None else keep_daily
    keep_weekly = config.BACKUP_KEEP_WEEKLY if keep_weekly is None else keep_weekly
    stem = stem or Path(config.DB_PATH).stem
    if keep_daily < 1:
        raise MaintenanceError("keep_daily must be at least 1")
    pattern = re.compile(rf"{re.escape(stem)}-(?P<ts>[0-9]{{8}}T[0-9]{{6}}Z)\.db", re.ASCII)
    latest_allowed = (now or datetime.now(UTC)) + timedelta(days=1)
    backups = []
    for f in output_dir.glob("*.db") if output_dir.is_dir() else []:
        m = pattern.fullmatch(f.name)
        if not m or f.is_symlink() or not f.is_file():
            continue
        try:
            ts = datetime.strptime(m.group("ts"), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
        except ValueError:
            continue                                             # e.g. month 13: not ours, leave it
        if ts > latest_allowed:
            continue                                             # future timestamp: never rank it "newest"
        backups.append((ts, f))
    backups.sort(reverse=True)                                   # newest first
    keep: set[Path] = set()
    days, weeks = [], []
    for ts, f in backups:
        day, week = ts.date(), ts.isocalendar()[:2]
        if day not in days and len(days) < keep_daily:
            days.append(day)
            keep.add(f)
        if week not in weeks and len(weeks) < keep_weekly:
            weeks.append(week)
            keep.add(f)
    if backups:
        keep.add(backups[0][1])
    deleted, failed = [], []
    for _, f in backups:
        if f in keep:
            continue
        try:
            f.unlink()
            deleted.append(f)
        except OSError as exc:                                   # one stuck file must not stop retention
            failed.append(f"{f}: {exc.strerror}")
    return {"kept": sorted(str(f) for f in keep), "deleted": sorted(str(f) for f in deleted), "failed": failed}


def scheduled_backup() -> None:
    """Job run by the application scheduler (CAG_BACKUP_INTERVAL_HOURS > 0): backup + retention."""
    import logging
    log = logging.getLogger("app.maintenance")
    try:
        info = backup()
        pruned = prune_backups()
        log.info("scheduled backup written: %s (%d assets); retention removed %d old backup(s)",
                 info.path.name, info.assets, len(pruned["deleted"]))
    except Exception:  # noqa: BLE001 - a failed backup must be visible but must not crash the scheduler
        log.exception("scheduled backup failed")


def restore(backup_file: Path, target: Path | None = None, force: bool = False) -> dict:
    """Restore a verified backup into `target` (default: the configured database).

    Never overwrites an existing database unless force=True; even then the
    current file is first saved as <target>.pre-restore-<UTC>.db. Stop the
    application before restoring over its active database.
    """
    backup_file = Path(backup_file)
    if target is None:
        _require_sqlite("restore")
    target = Path(target or config.DB_PATH)
    info = verify_backup(backup_file)
    if _same_file(backup_file, target):
        raise MaintenanceError("backup file and restore target are the same file")

    safety_copy = None
    if target.exists():
        if not force:
            raise MaintenanceError(
                f"{target} already exists. Restore into a new path, or stop the application "
                "and pass --force to replace it (a safety copy is kept).")
        safety_copy = target.with_name(f"{target.stem}.pre-restore-{_timestamp()}{target.suffix}")
        _copy_sqlite(target, safety_copy)

    target.parent.mkdir(parents=True, exist_ok=True)
    staged = target.with_name(target.name + ".restoring")
    staged.unlink(missing_ok=True)
    _copy_sqlite(backup_file, staged)
    verify_backup(staged)
    try:
        for suffix in ("-wal", "-shm", "-journal"):      # stale sidecar files of the old DB
            Path(str(target) + suffix).unlink(missing_ok=True)
        os.replace(staged, target)                        # atomic on the same filesystem
    except PermissionError:
        staged.unlink(missing_ok=True)
        raise MaintenanceError(f"{target} is in use - stop the application, then restore again") from None
    restored = verify_backup(target)
    return {"restored_to": str(target), "assets": restored.assets, "from": str(backup_file),
            "backup_assets": info.assets, "safety_copy": str(safety_copy) if safety_copy else None}


def check() -> list[str]:
    """Configuration report. Passwords in CAG_DATABASE_URL are masked."""
    from . import database
    config.validate_runtime(check_db_path=not config.DATABASE_URL)
    if config.DATABASE_URL:
        database.configure()
        state = "reachable, schema ready" if database.check_ready() else "NOT ready (unreachable or schema missing)"
        db_line = f"database      {database.describe()} ({state})"
    else:
        db_line = f"database      {config.DB_PATH} ({'exists' if config.DB_PATH.exists() else 'will be created'})"
    lines = [
        f"python        {sys.version.split()[0]} (required >= {'.'.join(map(str, config.MIN_PYTHON))})",
        db_line,
        f"backups       {config.BACKUP_DIR}",
        f"log level     {config.LOG_LEVEL}",
    ]
    if not config.DATABASE_URL and _same_file(config.BACKUP_DIR, config.DB_PATH.parent):
        lines.append("warning       CAG_BACKUP_DIR is the database directory - keep backups separate")
    return lines


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Repeat password: "):
            raise MaintenanceError("passwords do not match")
    if not password:
        raise MaintenanceError("password must not be empty")
    return password


def _cli_context():
    """Audit actor for CLI actions: the operating-system account that ran the command."""
    from .audit.service import AuditContext
    try:
        os_user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no login name available (e.g. some containers)
        os_user = "unknown"
    return AuditContext(user_id=None, username=f"cli:{os_user}"[:64], ip_address=None)


def create_user(username: str, role: str, password: str, display_name: str | None = None) -> str:
    from .auth import passwords
    from .auth import service as auth
    from .auth.permissions import Role
    init_database()
    from . import database
    with next(database.get_session()) as session:
        try:
            user = auth.create_user(session, _cli_context(), username, password, Role(role), display_name)
        except (auth.UserConflict, passwords.PasswordPolicyError, ValueError) as exc:
            raise MaintenanceError(str(exc)) from None
        return f"created user '{user.username}' with role {user.role.value}"


def reset_password(username: str, password: str) -> str:
    """Emergency access recovery: new password, account unlocked and re-enabled."""
    from .auth import passwords
    from .auth import service as auth
    init_database()
    from . import database
    ctx = _cli_context()
    with next(database.get_session()) as session:
        user = auth.get_user_by_username(session, username)
        if user is None:
            raise MaintenanceError(f"user '{username}' does not exist")
        try:
            auth.set_password(session, ctx, user.id, password)
        except passwords.PasswordPolicyError as exc:
            raise MaintenanceError(str(exc)) from None
        if not user.is_active:
            auth.update_user(session, ctx, user.id, is_active=True)
        return f"password for '{user.username}' reset; account unlocked and active"


def seed_demo(dataset: str = "cybermock") -> dict:
    """Load a fictional demo inventory through the normal service layer (validation + audit log).

    Idempotent: assets are matched by name among assets carrying the demo tag; existing ones
    are left untouched, so running it twice creates no duplicates.
    """
    from sqlalchemy import select

    from .assets import service as assets
    from .assets.models import Asset, AssetTag, LifecycleStatus
    from .assets.schemas import AssetCreate
    from .demo import cybermock

    if dataset != "cybermock":
        raise MaintenanceError(f"unknown demo dataset '{dataset}' (available: cybermock)")
    init_database()
    from . import database
    ctx = _cli_context()
    created = skipped = 0
    with next(database.get_session()) as session:
        existing = set(session.scalars(
            select(Asset.name).where(Asset.tag_rows.any(AssetTag.tag == cybermock.DEMO_TAG))).all())
        for item in cybermock.inventory():
            if item["name"] in existing:
                skipped += 1
                continue
            try:
                data = AssetCreate(**item)
            except ValueError as exc:
                raise MaintenanceError(f"invalid demo asset {item['name']}: {exc}") from None
            asset = assets.create_asset(session, data, ctx)
            if item["name"] in cybermock.INACTIVE_NAMES:
                assets.set_status(session, asset.id, LifecycleStatus.INACTIVE, ctx)
            created += 1
    return {"dataset": dataset, "created": created, "skipped": skipped}


def list_users() -> list[str]:
    from .auth import service as auth
    init_database()
    from . import database
    with next(database.get_session()) as session:
        return [f"{u.username:<24} {u.role.value:<8} {'active' if u.is_active else 'disabled':<9} "
                f"last login: {u.last_login_at.isoformat(timespec='seconds') if u.last_login_at else '-'}"
                for u in auth.list_users(session)]


def init_database() -> str:
    from . import database
    database.configure()                    # CAG_DATABASE_URL if set, else the SQLite file CAG_DB_PATH
    database.ensure_schema()
    if not database.check_ready():
        raise MaintenanceError("database initialized but readiness check failed")
    return f"database ready at {database.describe()}"


def _require_sqlite(action: str) -> None:
    if config.DATABASE_URL:
        raise MaintenanceError(
            f"{action} works on the local SQLite file only. CAG_DATABASE_URL points to a database server, "
            "which is backed up by its provider (Azure PostgreSQL: automated backups / point-in-time restore); "
            "use pg_dump for an additional export.")


def _copy_order() -> tuple[str, ...]:
    """Every ORM table, parents before children (foreign-key order)."""
    from . import database
    database._register_all_models()
    return tuple(t.name for t in database.Base.metadata.sorted_tables)


def copy_to_server(source: Path, target_url: str | None = None) -> dict:
    """Copy all data from a SQLite file into an EMPTY database server (e.g. the Azure PostgreSQL test DB).

    The target schema is created first; the copy runs in one transaction and refuses to touch a
    target that already contains data. Sequences are advanced past the copied ids.
    """
    from sqlalchemy import Integer, MetaData, create_engine, func, insert, select, text

    from . import database

    target_url = target_url or config.DATABASE_URL
    if not target_url or target_url.startswith("sqlite"):
        raise MaintenanceError("set CAG_DATABASE_URL to the target PostgreSQL database first")
    source = Path(source)
    verify_backup(source)                                   # readable, intact, CyberAsset Guard schema

    database.configure(target_url)
    database.ensure_schema()                                # migrations: schema + alembic_version
    copy_order = _copy_order()
    target = database.get_engine()
    tmeta = MetaData()
    tmeta.reflect(target, only=copy_order)
    with target.connect() as conn:
        not_empty = [t for t in copy_order if conn.execute(select(func.count()).select_from(tmeta.tables[t])).scalar()]
    if not_empty:
        raise MaintenanceError(f"target database is not empty (tables with data: {', '.join(not_empty)}) - "
                               "copy only into a fresh database")

    src = create_engine(f"sqlite:///{source}")
    smeta = MetaData()
    smeta.reflect(src)
    copied: dict[str, int] = {}
    try:
        with src.connect() as s, target.begin() as t:
            for name in copy_order:
                if name not in smeta.tables:
                    continue
                columns = set(tmeta.tables[name].c.keys())
                rows = [{k: v for k, v in r._mapping.items() if k in columns}
                        for r in s.execute(select(smeta.tables[name]))]
                if rows:
                    t.execute(insert(tmeta.tables[name]), rows)
                copied[name] = len(rows)
            for name in copy_order:                         # continue ids after the copied rows
                id_col = tmeta.tables[name].c.get("id")
                if id_col is not None and isinstance(id_col.type, Integer) and copied.get(name):
                    t.execute(text(f"SELECT setval(pg_get_serial_sequence('{name}', 'id'), "  # noqa: S608
                                   f"(SELECT MAX(id) FROM {name}))"))  # 'name' is an ORM table name, not user input
    finally:
        src.dispose()
    return {"target": database.describe(), "copied": copied}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.maintenance",
                                     description="CyberAsset Guard operations")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="validate configuration and runtime")
    sub.add_parser("init-db", help="create the database schema (idempotent)")
    p_b = sub.add_parser("backup", help="create a consistent, verified backup")
    p_b.add_argument("--output-dir", type=Path, help=f"default: CAG_BACKUP_DIR ({config.BACKUP_DIR})")
    p_p = sub.add_parser("prune-backups", help="apply the backup retention policy")
    p_p.add_argument("--keep-daily", type=int, help=f"default: CAG_BACKUP_KEEP_DAILY ({config.BACKUP_KEEP_DAILY})")
    p_p.add_argument("--keep-weekly", type=int, help=f"default: CAG_BACKUP_KEEP_WEEKLY ({config.BACKUP_KEEP_WEEKLY})")
    p_v = sub.add_parser("verify", help="check a backup file")
    p_v.add_argument("backup_file", type=Path)
    p_r = sub.add_parser("restore", help="restore a backup")
    p_r.add_argument("backup_file", type=Path)
    p_r.add_argument("--target", type=Path, required=True,
                     help="database file to create; use the CAG_DB_PATH file only with --force "
                          "and while the application is stopped")
    p_r.add_argument("--force", action="store_true",
                     help="replace an existing target (a safety copy is written first)")
    p_cu = sub.add_parser("create-user", help="create a user account (e.g. the first administrator)")
    p_cu.add_argument("username")
    p_cu.add_argument("--role", choices=["viewer", "analyst", "admin"], default="viewer")
    p_cu.add_argument("--display-name")
    p_cu.add_argument("--password-stdin", action="store_true",
                      help="read the password from stdin instead of prompting (for scripts/Docker)")
    p_rp = sub.add_parser("reset-password", help="set a new password, unlock and re-enable an account")
    p_rp.add_argument("username")
    p_rp.add_argument("--password-stdin", action="store_true")
    sub.add_parser("list-users", help="list user accounts")
    p_cp = sub.add_parser("copy-to-server",
                          help="copy a SQLite database into the EMPTY database at CAG_DATABASE_URL")
    p_cp.add_argument("source", type=Path, help="SQLite file, e.g. cyberasset_guard.db")
    p_sd = sub.add_parser("seed-demo", help="load the fictional Cybermock demo inventory (idempotent)")
    p_sd.add_argument("--dataset", default="cybermock", choices=["cybermock"])
    args = parser.parse_args(argv)

    try:
        if args.cmd == "check":
            print("\n".join(check()))
        elif args.cmd == "init-db":
            print(init_database())
        elif args.cmd == "backup":
            info = backup(output_dir=args.output_dir)
            print(f"backup written: {info.path} ({info.assets} assets, integrity {info.integrity})")
        elif args.cmd == "prune-backups":
            result = prune_backups(keep_daily=args.keep_daily, keep_weekly=args.keep_weekly)
            print(f"kept {len(result['kept'])} backup(s), deleted {len(result['deleted'])}")
        elif args.cmd == "verify":
            info = verify_backup(args.backup_file)
            print(f"ok: {info.path} ({info.assets} assets, {len(info.tables)} tables)")
        elif args.cmd == "restore":
            result = restore(args.backup_file, args.target, args.force)
            print(f"restored {result['assets']} assets to {result['restored_to']}")
            if result["safety_copy"]:
                print(f"previous database saved as {result['safety_copy']}")
        elif args.cmd == "create-user":
            print(create_user(args.username, args.role, _read_password(args.password_stdin),
                              args.display_name))
        elif args.cmd == "reset-password":
            print(reset_password(args.username, _read_password(args.password_stdin)))
        elif args.cmd == "list-users":
            print("\n".join(list_users()) or "no users")
        elif args.cmd == "copy-to-server":
            result = copy_to_server(args.source)
            print(f"copied into {result['target']}:")
            print("\n".join(f"  {t:<16} {n} rows" for t, n in result["copied"].items()))
        elif args.cmd == "seed-demo":
            result = seed_demo(args.dataset)
            print(f"demo dataset '{result['dataset']}': {result['created']} assets created, "
                  f"{result['skipped']} already present")
    except (MaintenanceError, config.ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

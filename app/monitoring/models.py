"""SQLAlchemy models for the Monitoring module (ASSET-48).

Replaces the former raw-sqlite3 layer (app/db.py) so the whole application uses
one data-access style (see app/database.py). The table and column names are
unchanged, so existing databases keep working unaltered.

Timestamps stay as ISO-8601 strings (as the sqlite3 layer stored them) to remain
byte-compatible with existing rows; switching them to UTCDateTime is out of scope
for this persistence migration.
"""
from __future__ import annotations

from sqlalchemy import ForeignKey, Index
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def as_dict(obj) -> dict:
    """Plain dict of an ORM row's columns (keeps the API/CLI shape the sqlite3
    layer produced with `dict(sqlite3.Row)`)."""
    return {attr.key: getattr(obj, attr.key) for attr in sa_inspect(obj).mapper.column_attrs}


class MonitoredAsset(Base):
    """A host discovered by scanning, keyed by IP. Distinct from Asset Management's
    `asset_inventory` (managed assets); linking the two is a later story (ASSET-64)."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(unique=True)
    hostname: Mapped[str | None] = mapped_column(default=None)
    first_seen: Mapped[str]
    last_seen: Mapped[str | None] = mapped_column(default=None)
    # Link to a managed asset (asset_inventory.id, a UUID string) — set by the
    # matching service (ASSET-64). Kept by asset id, so an asset's IP can change
    # without breaking the link. No DB foreign key: managed assets are
    # deactivated, never deleted, so there is nothing to cascade.
    managed_asset_id: Mapped[str | None] = mapped_column(index=True, default=None)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_type: Mapped[str]                       # 'discovery' | 'port' | 'version'
    target: Mapped[str]
    status: Mapped[str]                          # 'running' | 'completed' | 'failed'
    started_at: Mapped[str]
    finished_at: Mapped[str | None] = mapped_column(default=None)
    args: Mapped[str | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(default=None)


class HostResult(Base):
    __tablename__ = "host_results"
    __table_args__ = (Index("idx_host_results_scan", "scan_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), default=None)
    ip: Mapped[str]
    hostname: Mapped[str | None] = mapped_column(default=None)
    state: Mapped[str]                           # 'up' | 'down'
    reason: Mapped[str | None] = mapped_column(default=None)
    latency_s: Mapped[float | None] = mapped_column(default=None)


class PortResult(Base):
    __tablename__ = "port_results"
    __table_args__ = (Index("idx_port_results_scan", "scan_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), default=None)
    ip: Mapped[str]
    port: Mapped[int]
    protocol: Mapped[str]                        # 'tcp' | 'udp'
    state: Mapped[str]                           # 'open' | 'open|filtered'
    service: Mapped[str | None] = mapped_column(default=None)
    product: Mapped[str | None] = mapped_column(default=None)
    version: Mapped[str | None] = mapped_column(default=None)
    extrainfo: Mapped[str | None] = mapped_column(default=None)


class Schedule(Base):
    __tablename__ = "schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_type: Mapped[str]
    target: Mapped[str]
    ports: Mapped[str | None] = mapped_column(default=None)
    interval_seconds: Mapped[int]
    enabled: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[str]
    last_run_at: Mapped[str | None] = mapped_column(default=None)
    last_scan_id: Mapped[int | None] = mapped_column(default=None)
    last_error: Mapped[str | None] = mapped_column(default=None)


class Change(Base):
    __tablename__ = "changes"
    __table_args__ = (Index("idx_changes_scan", "scan_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    prev_scan_id: Mapped[int | None] = mapped_column(default=None)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), default=None)
    ip: Mapped[str]
    change_type: Mapped[str]
    port: Mapped[int | None] = mapped_column(default=None)
    protocol: Mapped[str | None] = mapped_column(default=None)
    detail: Mapped[str | None] = mapped_column(default=None)
    detected_at: Mapped[str]

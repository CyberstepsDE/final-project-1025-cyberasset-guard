"""Asset Management business logic.

All queries go through SQLAlchemy expressions with bound parameters - user
input is never concatenated into SQL.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from ..audit import service as audit
from ..database import utcnow
from .models import Asset, AssetTag, AssetType, Criticality, Environment, InternetFacing, LifecycleStatus
from .schemas import AssetCreate, AssetUpdate


class AssetNotFound(LookupError):
    def __init__(self, asset_id: str):
        super().__init__(f"Asset '{asset_id}' was not found")
        self.asset_id = asset_id


@dataclass
class AssetFilter:
    q: str | None = None                      # name, IP address or hostname (substring)
    environment: Environment | None = None
    criticality: Criticality | None = None
    asset_type: AssetType | None = None
    status: LifecycleStatus | None = None
    internet_facing: InternetFacing | None = None
    tag: str | None = None


SORTS = {
    "updated": (Asset.updated_at.desc(),),
    "name": (func.lower(Asset.name), Asset.created_at),
    "criticality": (
        case({"critical": 0, "high": 1, "medium": 2, "low": 3}, value=Asset.criticality),
        func.lower(Asset.name),
    ),
}


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


AUDITED_FIELDS = ("name", "asset_type", "environment", "criticality", "internet_facing", "status",
                  "ip_address", "hostname", "owner", "description")


def _snapshot(asset: Asset) -> dict:
    values = {f: getattr(asset, f) for f in AUDITED_FIELDS}
    values = {k: (v.value if hasattr(v, "value") else v) for k, v in values.items()}
    values["tags"] = asset.tags
    return values


def create_asset(session: Session, data: AssetCreate, ctx: audit.AuditContext = audit.SYSTEM) -> Asset:
    now = utcnow()
    values = data.model_dump(exclude={"tags"})
    asset = Asset(**values, status=LifecycleStatus.ACTIVE, created_at=now, updated_at=now)
    asset.set_tags(data.tags)
    session.add(asset)
    session.flush()
    audit.record(session, ctx, "asset.create", target_type="asset", target_id=asset.id,
                 target_label=asset.name, details={"values": _snapshot(asset)})
    from ..dashboard import service as dashboard  # lazy: the dashboard reads asset data
    dashboard.record_snapshot_safely(session)              # active-asset count / coverage changed
    session.commit()                                   # asset and audit entry in one transaction
    return asset


def get_asset(session: Session, asset_id: str) -> Asset:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise AssetNotFound(asset_id)
    return asset


def list_assets(session: Session, filters: AssetFilter, sort: str = "updated",
                limit: int = 100, offset: int = 0) -> tuple[list[Asset], int]:
    stmt = select(Asset)
    if filters.q:
        pattern = f"%{_escape_like(filters.q.strip())}%"
        stmt = stmt.where(or_(
            Asset.name.ilike(pattern, escape="\\"),
            Asset.ip_address.ilike(pattern, escape="\\"),
            Asset.hostname.ilike(pattern, escape="\\"),
        ))
    for column, value in ((Asset.environment, filters.environment),
                          (Asset.criticality, filters.criticality),
                          (Asset.asset_type, filters.asset_type),
                          (Asset.status, filters.status),
                          (Asset.internet_facing, filters.internet_facing)):
        if value is not None:
            stmt = stmt.where(column == value)
    if filters.tag:
        stmt = stmt.where(Asset.tag_rows.any(AssetTag.tag == filters.tag.strip().lower()))

    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = session.scalars(stmt.order_by(*SORTS[sort]).limit(limit).offset(offset)).all()
    return list(rows), total


def update_asset(session: Session, asset_id: str, data: AssetUpdate,
                 ctx: audit.AuditContext = audit.SYSTEM) -> Asset:
    """Apply a partial update. id and created_at are never touched.
    Changed fields are audit-logged (before/after) in the same transaction."""
    asset = get_asset(session, asset_id)
    before = _snapshot(asset)
    changes = data.model_dump(exclude_unset=True)
    tags = changes.pop("tags", None)

    changed = False
    for field, value in changes.items():
        if getattr(asset, field) != value:
            setattr(asset, field, value)
            changed = True
            if field == "status":
                asset.deactivated_at = utcnow() if value == LifecycleStatus.INACTIVE else None
    if tags is not None and tags != asset.tags:
        asset.set_tags(tags)
        changed = True

    if changed:
        asset.updated_at = utcnow()
        diff = audit.diff(before, _snapshot(asset))
        action = "asset.update"
        if set(diff) == {"status"}:
            action = "asset.deactivate" if asset.status == LifecycleStatus.INACTIVE else "asset.activate"
        audit.record(session, ctx, action, target_type="asset", target_id=asset.id,
                     target_label=asset.name, details={"changes": diff})
        from ..risk import service as risk  # lazy: risk depends on the asset models
        if set(diff) & risk.RISK_CONTEXT_FIELDS:
            risk.rescore_asset(session, asset, trigger="asset_change")   # risk follows the new context
        if set(diff) & (risk.RISK_CONTEXT_FIELDS | {"status"}):
            from ..dashboard import service as dashboard
            dashboard.record_snapshot_safely(session)    # organisation posture (active assets) changed
        session.commit()
    return asset


def set_status(session: Session, asset_id: str, status: LifecycleStatus,
               ctx: audit.AuditContext = audit.SYSTEM) -> Asset:
    """Deactivate / reactivate. The record is kept so future findings can still reference it."""
    return update_asset(session, asset_id, AssetUpdate(status=status), ctx)

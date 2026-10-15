"""Analyst actions on findings and manual software. Every change is audit-logged
in the same transaction."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..assets.models import Asset
from ..audit import service as audit
from ..database import utcnow
from .models import CLOSED_STATUSES, AssetSoftware, Finding, FindingStatus

# Statuses an analyst may set. resolved / verified_fixed are only set by correlation
# after a re-scan, so "fixed" is always backed by evidence.
MANUAL_STATUSES = frozenset({FindingStatus.OPEN, FindingStatus.IN_REMEDIATION, FindingStatus.ACCEPTED_RISK})


class NotFound(LookupError):
    pass


class InvalidChange(ValueError):
    pass


def get_finding(session: Session, finding_id: int) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise NotFound(f"Finding {finding_id} was not found")
    return finding


def _snapshot(f: Finding) -> dict:
    return {"status": f.status.value, "status_reason": f.status_reason, "ticket_key": f.ticket_key}


def update_finding(session: Session, ctx: audit.AuditContext, finding_id: int, *,
                   status: FindingStatus | None = None, reason: str | None = None,
                   ticket_key: str | None = None) -> Finding:
    finding = get_finding(session, finding_id)
    before = _snapshot(finding)
    reason = (reason or "").strip() or None

    if status is not None and status != finding.status:
        if status not in MANUAL_STATUSES:
            raise InvalidChange("'resolved' and 'verified_fixed' are set automatically after a re-scan")
        if finding.status in CLOSED_STATUSES:
            raise InvalidChange("The finding is closed; it reopens automatically if the vulnerability returns")
        if status == FindingStatus.ACCEPTED_RISK and not reason:
            raise InvalidChange("Accepting a risk requires a reason")
        finding.status = status
        finding.status_reason = reason
        finding.status_changed_at = utcnow()
    elif reason is not None:
        finding.status_reason = reason
    if ticket_key is not None:
        finding.ticket_key = ticket_key.strip() or None

    changes = audit.diff(before, _snapshot(finding))
    if changes:
        action = "finding.accept_risk" if finding.status == FindingStatus.ACCEPTED_RISK and "status" in changes \
            else "finding.update"
        audit.record(session, ctx, action, target_type="finding", target_id=str(finding.id),
                     target_label=f"{finding.cve_id} on {finding.asset.name}", details=changes)
        if "status" in changes:
            from ..risk import service as risk  # lazy: risk depends on the correlation models
            risk.rescore_asset(session, finding.asset, trigger="finding_status")   # open / accepted / max
            from ..dashboard import service as dashboard
            dashboard.record_snapshot_safely(session)
    session.commit()
    return finding


def list_software(session: Session, asset: Asset) -> list[AssetSoftware]:
    return list(session.scalars(select(AssetSoftware).where(AssetSoftware.asset_id == asset.id)
                                .order_by(AssetSoftware.product, AssetSoftware.id)))


def add_software(session: Session, ctx: audit.AuditContext, asset: Asset, product: str,
                 version: str | None, cpe: str | None) -> AssetSoftware:
    sw = AssetSoftware(asset_id=asset.id, product=product, version=version, cpe=cpe,
                       created_at=utcnow(), created_by=ctx.username)
    session.add(sw)
    session.flush()
    audit.record(session, ctx, "asset.software_add", target_type="asset", target_id=asset.id,
                 target_label=asset.name, details={"software_id": sw.id, "product": product,
                                                   "version": version, "cpe": cpe})
    session.commit()
    return sw


def remove_software(session: Session, ctx: audit.AuditContext, asset: Asset, software_id: int) -> None:
    sw = session.get(AssetSoftware, software_id)
    if sw is None or sw.asset_id != asset.id:
        raise NotFound(f"Software entry {software_id} was not found on this asset")
    audit.record(session, ctx, "asset.software_remove", target_type="asset", target_id=asset.id,
                 target_label=asset.name, details={"software_id": sw.id, "product": sw.product,
                                                   "version": sw.version})
    session.delete(sw)  # findings stay; they close on the next correlation run
    session.commit()

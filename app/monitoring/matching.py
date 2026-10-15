"""Link discovered hosts (Monitoring `assets`) to managed assets (asset_inventory).

Matching rule (documented): a discovered host is matched to **active** managed
assets by exact IP address; if none match by IP, by exact host name. Exactly one
match links automatically; more than one is *ambiguous* and left for an analyst
to decide; none leaves the host as an unmanaged candidate. The link is stored by
asset id, so an asset's IP can change without breaking it. (ASSET-64)
"""
from __future__ import annotations

from sqlalchemy import func, select

from ..assets import service as assets_service
from ..assets.models import Asset, LifecycleStatus
from ..audit import service as audit
from .models import MonitoredAsset, as_dict


class HostNotFound(LookupError):
    """The monitoring host id does not exist."""


def find_match(session, ip: str | None, hostname: str | None = None) -> tuple[str | None, bool]:
    """Return (asset_id, ambiguous): the single active asset matching by IP (then
    hostname), or (None, True) if several match, or (None, False) if none do."""
    def active_ids(column, value):
        if not value:
            return []
        return list(session.scalars(
            select(Asset.id).where(func.lower(column) == value.lower(),
                                   Asset.status == LifecycleStatus.ACTIVE)))

    ids = active_ids(Asset.ip_address, ip) or active_ids(Asset.hostname, hostname)
    if len(ids) == 1:
        return ids[0], False
    return None, len(ids) > 1


def auto_link(session, host: MonitoredAsset) -> bool:
    """Link a freshly seen host to an unambiguous active asset, if not already
    linked. Audited as a system action. Returns True if it linked."""
    if host.managed_asset_id is not None:
        return False
    asset_id, ambiguous = find_match(session, host.ip, host.hostname)
    if asset_id is None or ambiguous:
        return False
    host.managed_asset_id = asset_id
    audit.record(session, audit.SYSTEM, "monitoring.host_linked", target_type="asset",
                 target_id=asset_id, details={"host_id": host.id, "host_ip": host.ip, "auto": True})
    return True


# --- analyst actions (require assets:write; called with a request session) ---

def list_candidates(session) -> list[dict]:
    """Unmanaged discovered hosts, each with its suggested match (if any)."""
    hosts = session.scalars(
        select(MonitoredAsset).where(MonitoredAsset.managed_asset_id.is_(None))
        .order_by(MonitoredAsset.ip)).all()
    candidates = []
    for h in hosts:
        asset_id, ambiguous = find_match(session, h.ip, h.hostname)
        candidates.append({"host_id": h.id, "ip": h.ip, "hostname": h.hostname,
                           "suggested_asset_id": asset_id, "ambiguous": ambiguous})
    return candidates


def link_host(session, host_id: int, asset_id: str, ctx) -> dict:
    host = session.get(MonitoredAsset, host_id)
    if host is None:
        raise HostNotFound(f"host {host_id} not found")
    asset = session.get(Asset, asset_id)
    if asset is None or asset.status != LifecycleStatus.ACTIVE:
        raise ValueError("asset not found or not active")
    host.managed_asset_id = asset.id
    audit.record(session, ctx, "monitoring.host_linked", target_type="asset",
                 target_id=asset.id, target_label=asset.name,
                 details={"host_id": host_id, "host_ip": host.ip})
    session.commit()
    return as_dict(host)


def unlink_host(session, host_id: int, ctx) -> dict:
    host = session.get(MonitoredAsset, host_id)
    if host is None:
        raise HostNotFound(f"host {host_id} not found")
    previous = host.managed_asset_id
    host.managed_asset_id = None
    audit.record(session, ctx, "monitoring.host_unlinked", target_type="asset",
                 target_id=previous, details={"host_id": host_id, "host_ip": host.ip})
    session.commit()
    return as_dict(host)


def create_asset_from_host(session, host_id: int, data, ctx) -> dict:
    """Create a managed asset from an unmanaged host and link the host to it."""
    host = session.get(MonitoredAsset, host_id)
    if host is None:
        raise HostNotFound(f"host {host_id} not found")
    asset = assets_service.create_asset(session, data, ctx)      # records asset.create, commits
    host.managed_asset_id = asset.id
    audit.record(session, ctx, "monitoring.host_linked", target_type="asset",
                 target_id=asset.id, target_label=asset.name,
                 details={"host_id": host_id, "host_ip": host.ip, "created": True})
    session.commit()
    return {"asset_id": asset.id, "host": as_dict(host)}

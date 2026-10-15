"""Where an asset's software comes from: Monitoring version scans + manual entries.

Until S4.2 links monitoring hosts to inventory assets, a scan host belongs to an
asset when the IP address matches exactly one *active* asset. IPs shared by
several active assets are ambiguous and skipped (reported as a warning).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..assets.models import Asset, LifecycleStatus
from ..monitoring.models import HostResult, PortResult, Scan
from .models import AssetSoftware, SoftwareSource


@dataclass(frozen=True)
class SoftwareItem:
    product: str
    version: str | None
    source: SoftwareSource
    port: int | None = None
    protocol: str | None = None
    cpe: str | None = None


@dataclass
class AssetSoftwareView:
    items: list[SoftwareItem] = field(default_factory=list)
    scan_id: int | None = None          # version scan the scan items come from
    warnings: list[str] = field(default_factory=list)

    @property
    def scan_available(self) -> bool:
        return self.scan_id is not None


def latest_version_scan(session: Session, ip: str) -> tuple[int | None, list[SoftwareItem]]:
    """Open ports with a detected product from the newest completed version scan of `ip`."""
    scan_id = session.scalar(
        select(Scan.id).join(HostResult, HostResult.scan_id == Scan.id)
        .where(Scan.scan_type == "version", Scan.status == "completed",
               HostResult.ip == ip, HostResult.state == "up")
        .order_by(Scan.id.desc()).limit(1))
    if scan_id is None:
        return None, []
    ports = session.scalars(
        select(PortResult).where(PortResult.scan_id == scan_id, PortResult.ip == ip,
                                 PortResult.state.like("open%"), PortResult.product.is_not(None))
        .order_by(PortResult.port))
    items = [SoftwareItem(product=p.product, version=p.version, source=SoftwareSource.SCAN,
                          port=p.port, protocol=p.protocol) for p in ports if p.product]
    return scan_id, items


def collect(session: Session, asset: Asset) -> AssetSoftwareView:
    view = AssetSoftwareView()
    if asset.ip_address:
        sharing = session.scalar(select(func.count()).select_from(Asset).where(
            Asset.ip_address == asset.ip_address, Asset.status == LifecycleStatus.ACTIVE)) or 0
        if sharing > 1:
            view.warnings.append(f"IP {asset.ip_address} belongs to {sharing} active assets; scan data skipped")
        else:
            view.scan_id, view.items = latest_version_scan(session, asset.ip_address)

    for sw in session.scalars(select(AssetSoftware).where(AssetSoftware.asset_id == asset.id)):
        view.items.append(SoftwareItem(product=sw.product, version=sw.version,
                                       source=SoftwareSource.MANUAL, cpe=sw.cpe))
    return view


def assets_for_scan(session: Session, scan_id: int) -> list[str]:
    """Ids of active assets whose IP was up in the given scan."""
    ips = list(session.scalars(select(HostResult.ip).distinct().where(
        HostResult.scan_id == scan_id, HostResult.state == "up")))
    if not ips:
        return []
    return list(session.scalars(select(Asset.id).where(
        Asset.ip_address.in_(ips), Asset.status == LifecycleStatus.ACTIVE)))

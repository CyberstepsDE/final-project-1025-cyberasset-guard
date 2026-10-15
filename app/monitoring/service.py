"""Monitoring business logic: run a scan and persist it to the database.

Keeps the scanner (pure nmap I/O) separate from storage (SQLAlchemy via
app.database), so each can be tested on its own.
"""
from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime

from sqlalchemy import select

from .. import config
from ..assets.models import Asset
from ..database import session_scope
from . import diff, matching, scanner
from .models import Change, HostResult, MonitoredAsset, PortResult, Scan, as_dict

log = logging.getLogger(__name__)


class ScanBusyError(scanner.ScannerError):
    """Raised when CAG_SCAN_MAX_CONCURRENT scans are already running (ASSET-62)."""


# Bound how many scans run at once (this is a single-worker process, so an in-process
# counter is sufficient). API scan requests over the limit get 429; scheduled runs skip.
_scan_lock = threading.Lock()
_active_scans = 0


def _acquire_scan_slot() -> None:
    global _active_scans
    with _scan_lock:
        if _active_scans >= config.SCAN_MAX_CONCURRENT:
            raise ScanBusyError(
                f"too many scans already running (limit {config.SCAN_MAX_CONCURRENT}); try again shortly")
        _active_scans += 1


def _release_scan_slot() -> None:
    global _active_scans
    with _scan_lock:
        _active_scans = max(0, _active_scans - 1)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _upsert_asset(session, ip: str, hostname: str | None, seen_at: str) -> int:
    """Insert the asset if new, otherwise refresh hostname/last_seen. Returns id."""
    asset = session.scalar(select(MonitoredAsset).where(MonitoredAsset.ip == ip))
    if asset is None:
        asset = MonitoredAsset(ip=ip, hostname=hostname, first_seen=seen_at, last_seen=seen_at)
        session.add(asset)
        session.flush()                      # assign the autoincrement id
    else:
        asset.last_seen = seen_at
        if hostname is not None:              # keep a previously learned name (old COALESCE)
            asset.hostname = hostname
    matching.auto_link(session, asset)        # ASSET-64: link to a managed asset if unambiguous
    return asset.id


def _store_result(session, scan_id: int, result, seen_at: str) -> None:
    """Persist every host (and its ports) of a completed scan."""
    for h in result.hosts:
        asset_id = None
        if h.state == "up":
            asset_id = _upsert_asset(session, h.ip, h.hostname, seen_at)
        session.add(HostResult(
            scan_id=scan_id, asset_id=asset_id, ip=h.ip, hostname=h.hostname,
            state=h.state, reason=h.reason, latency_s=h.latency_s,
        ))
        for p in h.ports:
            session.add(PortResult(
                scan_id=scan_id, asset_id=asset_id, ip=h.ip, port=p.port, protocol=p.protocol,
                state=p.state, service=p.service, product=p.product,
                version=p.version, extrainfo=p.extrainfo,
            ))


def _run_scan(scan_type: str, target: str, scan_fn) -> int:
    """Shared scan runner, bounded by CAG_SCAN_MAX_CONCURRENT (ASSET-62).

    Raises ScanBusyError if the limit is already reached (no scan row is created)."""
    _acquire_scan_slot()
    try:
        return _run_scan_locked(scan_type, target, scan_fn)
    finally:
        _release_scan_slot()


def _run_scan_locked(scan_type: str, target: str, scan_fn) -> int:
    """Record the scan, execute `scan_fn`, store results. The scan row is always written
    (even on failure) so history is complete. `scan_fn` returns a scanner.ScanResult."""
    started = _now()
    with session_scope() as session:
        scan = Scan(scan_type=scan_type, target=target, status="running", started_at=started)
        session.add(scan)
        session.flush()
        scan_id = scan.id

    try:
        result = scan_fn()
    except scanner.ScannerError as exc:
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            scan.status, scan.finished_at, scan.error = "failed", _now(), str(exc)
        raise

    finished = _now()
    with session_scope() as session:
        _store_result(session, scan_id, result, finished)
        scan = session.get(Scan, scan_id)
        scan.status, scan.finished_at, scan.args = "completed", finished, result.args

    # Part 5: diff against the previous comparable scan. Never let a change
    # detection failure fail the scan itself.
    try:
        diff.detect_changes(scan_id)
    except Exception:  # noqa: BLE001, S110  # best-effort: a change-detection failure must not fail the scan
        pass

    # Block 3: correlate the scanned assets with CVE data in the background.
    if scan_type == "version":
        try:
            from ..correlation.jobs import schedule_after_scan
            schedule_after_scan(scan_id)
        except Exception:  # noqa: BLE001 - never fail the scan, but make the failure visible
            log.exception("could not schedule CVE correlation after scan %s", scan_id)
    return scan_id


def run_discovery(target: str) -> int:
    """Part 1 — run a discovery (reachability) scan and store it. Returns scan id."""
    return _run_scan("discovery", target, lambda: scanner.discover(target))


def run_port_scan(target: str, ports: str | None = None) -> int:
    """Part 2 — run an open-ports/services scan and store it. Returns scan id."""
    return _run_scan("port", target, lambda: scanner.port_scan(target, ports))


def run_version_scan(target: str, ports: str | None = None) -> int:
    """Part 3 — run a service version-detection scan and store it. Returns scan id."""
    return _run_scan("version", target, lambda: scanner.version_scan(target, ports))


# --- read helpers (used by the API and CLI) ---------------------------------

def list_scans(limit: int = 50) -> list[dict]:
    with session_scope() as session:
        rows = session.scalars(select(Scan).order_by(Scan.id.desc()).limit(limit)).all()
        return [as_dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return None
        hosts = session.scalars(
            select(HostResult).where(HostResult.scan_id == scan_id).order_by(HostResult.ip)
        ).all()
        ports = session.scalars(
            select(PortResult).where(PortResult.scan_id == scan_id)
            .order_by(PortResult.ip, PortResult.port)
        ).all()

        ports_by_ip: dict[str, list[dict]] = {}
        for p in ports:
            ports_by_ip.setdefault(p.ip, []).append(as_dict(p))

        out = as_dict(scan)
        out["hosts"] = []
        for h in hosts:
            host = as_dict(h)
            host["ports"] = ports_by_ip.get(h.ip, [])
            out["hosts"].append(host)

    out["changes"] = diff.list_changes(scan_id)  # Part 5: diff vs previous scan
    return out


def list_assets() -> list[dict]:
    with session_scope() as session:
        rows = session.scalars(select(MonitoredAsset).order_by(MonitoredAsset.ip)).all()
        return [as_dict(r) for r in rows]


def asset_scan_target(asset_id: str) -> str:
    """The scan target for a managed asset: its IP address, else its hostname (ASSET-66).
    The target comes from the asset record (never the client) and is still validated by the
    scanner's policy. Raises LookupError if the asset is unknown, ValueError if it has neither."""
    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise LookupError(f"asset {asset_id} not found")
        target = asset.ip_address or asset.hostname
        if not target:
            raise ValueError("this asset has no IP address or hostname to scan")
        return target


def scan_asset(asset_id: str, scan_type: str, ports: str | None = None) -> dict:
    """Run a scan of a managed asset on demand and return the stored result (ASSET-66)."""
    target = asset_scan_target(asset_id)
    if scan_type == "discovery":
        scan_id = run_discovery(target)
    elif scan_type == "port":
        scan_id = run_port_scan(target, ports)
    elif scan_type == "version":
        scan_id = run_version_scan(target, ports)
    else:
        raise ValueError(f"unknown scan_type '{scan_type}' (expected discovery, port or version)")
    return get_scan(scan_id)


def asset_monitoring_summary(asset_id: str) -> dict:
    """Monitoring summary for a managed asset (asset_inventory.id): the latest reachability,
    the open ports from the most recent port/version scan, and recent changes — across the
    discovered host(s) linked to it (MonitoredAsset.managed_asset_id). Returns a clear
    'not scanned' shape rather than fabricating data when there is nothing to show (ASSET-65)."""
    with session_scope() as session:
        host_ids = list(session.scalars(
            select(MonitoredAsset.id).where(MonitoredAsset.managed_asset_id == asset_id)))
        summary: dict = {"linked": bool(host_ids), "scanned": False, "last_scan": None,
                         "reachability": None, "ports": [], "recent_changes": []}
        if not host_ids:
            return summary

        # Latest reachability: the most recent host_result for any linked host, with its scan.
        latest = session.execute(
            select(HostResult, Scan).join(Scan, Scan.id == HostResult.scan_id)
            .where(HostResult.asset_id.in_(host_ids))
            .order_by(Scan.id.desc()).limit(1)).first()
        if latest is None:
            return summary
        host_result, scan = latest
        summary["scanned"] = True
        summary["last_scan"] = {"id": scan.id, "scan_type": scan.scan_type,
                                "started_at": scan.started_at, "finished_at": scan.finished_at}
        summary["reachability"] = {"ip": host_result.ip, "hostname": host_result.hostname,
                                   "state": host_result.state, "reason": host_result.reason,
                                   "latency_s": host_result.latency_s}

        # Open ports: from the most recent scan that produced ports for a linked host.
        latest_ports_scan = session.scalar(
            select(PortResult.scan_id).where(PortResult.asset_id.in_(host_ids))
            .order_by(PortResult.scan_id.desc()).limit(1))
        if latest_ports_scan is not None:
            rows = session.scalars(
                select(PortResult).where(PortResult.asset_id.in_(host_ids),
                                         PortResult.scan_id == latest_ports_scan)
                .order_by(PortResult.ip, PortResult.port)).all()
            summary["ports"] = [
                {k: getattr(p, k) for k in
                 ("ip", "port", "protocol", "state", "service", "product", "version", "extrainfo")}
                for p in rows]

        changes = session.scalars(
            select(Change).where(Change.asset_id.in_(host_ids))
            .order_by(Change.detected_at.desc(), Change.id.desc()).limit(20)).all()
        summary["recent_changes"] = [
            {k: getattr(c, k) for k in ("change_type", "port", "protocol", "detail", "detected_at")}
            for c in changes]
        return summary

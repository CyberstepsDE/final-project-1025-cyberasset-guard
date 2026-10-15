"""FastAPI routes for the Monitoring module."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import config
from ..assets.schemas import AssetCreate
from ..auth.dependencies import CurrentUser, require
from ..auth.permissions import Permission
from ..database import get_session, session_scope
from . import diff, matching, scanner, scheduler, service
from . import targets as target_policy

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


def _validate(request: Request, target: str, ports: str | None = None) -> None:
    """Reject malformed targets (422) and out-of-scope targets (403, audit-logged) before any scan."""
    try:
        target_policy.prepare(target)
        target_policy.validate_ports(ports)
    except target_policy.TargetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except target_policy.TargetNotAllowed as exc:
        from ..audit import service as audit
        from ..audit.models import Outcome
        ctx = getattr(request.state, "audit_ctx", None)
        if ctx is not None:
            audit.record_now(ctx, "monitoring.scope_denied", outcome=Outcome.DENIED, target_type="monitoring",
                             details={"path": request.url.path, "target": target[:200]})
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _scan_error(exc: scanner.ScannerError) -> HTTPException:
    if isinstance(exc, service.ScanBusyError):
        return HTTPException(status_code=429, detail=str(exc))
    if isinstance(exc, scanner.ScanScopeError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, scanner.ScanTargetError):
        return HTTPException(status_code=422, detail=str(exc))
    return HTTPException(status_code=502, detail=str(exc))


class DiscoveryRequest(BaseModel):
    target: str = Field(
        ...,
        description="nmap target: host, CIDR (192.168.1.0/24), range (.1-20), "
                    "octet list (.1,2,3), or several separated by spaces.",
        examples=["127.0.0.1", "192.168.1.0/24", "127.0.0.1 192.0.2.1"],
    )


class PortScanRequest(BaseModel):
    target: str = Field(
        ...,
        description="nmap target (host, CIDR, range, or space-separated list).",
        examples=["127.0.0.1", "192.168.1.0/24"],
    )
    ports: str | None = Field(
        None,
        description="Optional port spec, e.g. '22,80,443' or '1-1024'. "
                    "Defaults to nmap's top-1000 TCP ports.",
        examples=["22,80,443", "1-1024"],
    )


@router.post("/discover")
def discover(req: DiscoveryRequest, request: Request):
    """Part 1 — run a discovery / reachability scan and return the stored result."""
    _validate(request, req.target, None)
    try:
        scan_id = service.run_discovery(req.target)
    except scanner.ScannerError as exc:
        raise _scan_error(exc) from exc
    return service.get_scan(scan_id)


@router.post("/portscan")
def port_scan(req: PortScanRequest, request: Request):
    """Part 2 — run an open-ports / services scan and return the stored result."""
    _validate(request, req.target, req.ports)
    try:
        scan_id = service.run_port_scan(req.target, req.ports)
    except scanner.ScannerError as exc:
        raise _scan_error(exc) from exc
    return service.get_scan(scan_id)


@router.post("/versionscan")
def version_scan(req: PortScanRequest, request: Request):
    """Part 3 — run a service version-detection scan and return the stored result."""
    _validate(request, req.target, req.ports)
    try:
        scan_id = service.run_version_scan(req.target, req.ports)
    except scanner.ScannerError as exc:
        raise _scan_error(exc) from exc
    return service.get_scan(scan_id)


@router.get("/scans")
def list_scans(limit: int = Query(50, ge=1, le=500)):
    return service.list_scans(limit)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    scan = service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


@router.get("/assets")
def list_assets():
    return service.list_assets()


@router.get("/assets/{asset_id}/summary")
def asset_summary(asset_id: str):
    """Monitoring summary (reachability, open ports, recent changes) for a managed asset's
    linked discovered host(s). Returns a 'not scanned' shape when there is no data (ASSET-65)."""
    return service.asset_monitoring_summary(asset_id)


# --- ASSET-66: scan / schedule a managed asset from the UI -------------------
# POST endpoints are unsafe methods, so the router's require_by_method gates them with
# monitoring:run; the target is taken from the asset record and re-validated by the scanner.

class AssetScanRequest(BaseModel):
    scan_type: str = Field("version", description="discovery | port | version", examples=["version"])
    ports: str | None = Field(None, description="Optional port spec for port/version scans.",
                              examples=["22,80,443"])


class AssetScheduleRequest(BaseModel):
    scan_type: str = Field(..., examples=["version"])
    interval_seconds: int = Field(..., ge=1, le=30 * 24 * 3600,
                                  description="Minimum is CAG_SCAN_MIN_INTERVAL_SECONDS.", examples=[3600])
    ports: str | None = Field(None, examples=["22,80,443"])


@router.post("/assets/{asset_id}/scan")
def scan_asset(asset_id: str, req: AssetScanRequest):
    """Run a scan (discovery/port/version) of a managed asset on demand."""
    try:
        return service.scan_asset(asset_id, req.scan_type, req.ports)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except scanner.ScannerError as exc:
        raise _scan_error(exc) from exc


@router.get("/assets/{asset_id}/schedules")
def list_asset_schedules(asset_id: str):
    """Recurring scan schedules whose target is this asset's IP/hostname."""
    try:
        target = service.asset_scan_target(asset_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError:
        return []                                   # no scannable target -> no schedules
    return [s for s in scheduler.list_schedules() if s["target"] == target]


@router.post("/assets/{asset_id}/schedules")
def create_asset_schedule(asset_id: str, req: AssetScheduleRequest):
    """Create a recurring scan schedule for a managed asset (target taken from the asset)."""
    try:
        target = service.asset_scan_target(asset_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if req.interval_seconds < config.SCAN_MIN_INTERVAL_SECONDS:
        raise HTTPException(status_code=422, detail=f"interval_seconds must be at least "
                            f"{config.SCAN_MIN_INTERVAL_SECONDS} (CAG_SCAN_MIN_INTERVAL_SECONDS)")
    try:
        return scheduler.add_schedule(req.scan_type, target, req.interval_seconds, req.ports)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# --- Part 4: scheduled scans ------------------------------------------------

class ScheduleRequest(BaseModel):
    scan_type: str = Field(
        ..., description="Which scan to run on a schedule.",
        examples=["discovery", "port", "version"],
    )
    target: str = Field(..., description="nmap target.", examples=["127.0.0.1"])
    interval_seconds: int = Field(
        ..., ge=1, le=30 * 24 * 3600,
        description="How often to run the scan, in seconds (minimum: CAG_SCAN_MIN_INTERVAL_SECONDS, default 900).",
        examples=[3600],
    )
    ports: str | None = Field(
        None, description="Optional port spec for port/version scans.",
        examples=["22,80,443"],
    )


@router.post("/schedules")
def create_schedule(req: ScheduleRequest, request: Request):
    """Create a recurring scan schedule (runs an initial scan immediately)."""
    if req.interval_seconds < config.SCAN_MIN_INTERVAL_SECONDS:
        raise HTTPException(status_code=422, detail=f"interval_seconds must be at least "
                                                    f"{config.SCAN_MIN_INTERVAL_SECONDS} (CAG_SCAN_MIN_INTERVAL_SECONDS)")
    _validate(request, req.target, req.ports)
    try:
        return scheduler.add_schedule(
            req.scan_type, req.target, req.interval_seconds, req.ports
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/schedules")
def list_schedules():
    return scheduler.list_schedules()


@router.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: int):
    if not scheduler.remove_schedule(schedule_id):
        raise HTTPException(status_code=404, detail="schedule not found")
    return {"deleted": schedule_id}


# --- Part 5: change detection -----------------------------------------------

@router.get("/changes")
def list_changes(scan_id: int | None = None, limit: int = Query(100, ge=1, le=500)):
    """Change log (newest first). Optionally filter to a single scan."""
    return diff.list_changes(scan_id, limit)


# --- ASSET-64: link discovered hosts to managed assets ----------------------
# Linking/creating assets requires assets:write (not just monitoring:run).

class LinkRequest(BaseModel):
    asset_id: str = Field(..., description="asset_inventory id (UUID) to link this host to.")


@router.get("/candidates")
def list_candidates():
    """Unmanaged discovered hosts with their suggested managed-asset match, if any."""
    with session_scope() as session:
        return matching.list_candidates(session)


@router.post("/hosts/{host_id}/link")
def link_host(host_id: int, req: LinkRequest,
              current: CurrentUser = Depends(require(Permission.ASSETS_WRITE)),
              session: Session = Depends(get_session)):
    """Manually link a discovered host to a managed asset."""
    try:
        return matching.link_host(session, host_id, req.asset_id, current.ctx)
    except matching.HostNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/hosts/{host_id}/unlink")
def unlink_host(host_id: int,
                current: CurrentUser = Depends(require(Permission.ASSETS_WRITE)),
                session: Session = Depends(get_session)):
    """Remove the link between a discovered host and its managed asset."""
    try:
        return matching.unlink_host(session, host_id, current.ctx)
    except matching.HostNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/hosts/{host_id}/create-asset", status_code=201)
def create_asset_from_host(host_id: int, req: AssetCreate,
                           current: CurrentUser = Depends(require(Permission.ASSETS_WRITE)),
                           session: Session = Depends(get_session)):
    """Create a managed asset from an unmanaged host (prefilled by the UI) and link it."""
    try:
        return matching.create_asset_from_host(session, host_id, req, current.ctx)
    except matching.HostNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

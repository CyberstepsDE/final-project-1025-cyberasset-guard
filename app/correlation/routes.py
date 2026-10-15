"""REST API for vulnerability correlation (E5).

Reading findings needs `findings:read` (all roles); changing them and starting
correlation needs `findings:write` (analyst, admin). Manual software belongs to
the asset, so it uses `assets:read` / `assets:write`.
"""
from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..assets.models import Asset, LifecycleStatus
from ..audit import service as audit
from ..auth.dependencies import CurrentUser, get_current_user, require
from ..auth.permissions import Permission
from ..database import get_session
from ..risk import service as risk
from ..risk.models import FindingRisk
from . import jobs, kev, service
from .engine import ACTIVE_RUN_STATUSES, CorrelationBusy, queue_run
from .models import CorrelationRun, Cve, FeedSync, Finding, FindingStatus
from .schemas import (
    CorrelationRunRead,
    FindingList,
    FindingRead,
    FindingUpdate,
    RunRequest,
    ScheduleStatus,
    SoftwareCreate,
    SoftwareRead,
)

# Router-level login guard (defence in depth); each endpoint also checks its permission.
router = APIRouter(tags=["vulnerability correlation"], dependencies=[Depends(get_current_user)])

can_read = require(Permission.FINDINGS_READ)
can_write = require(Permission.FINDINGS_WRITE)
assets_read = require(Permission.ASSETS_READ)
assets_write = require(Permission.ASSETS_WRITE)

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
NOT_FOUND = {404: {"description": "Not found"}}


def _asset(session: Session, asset_id: str) -> Asset:
    try:
        asset = session.get(Asset, str(uuid.UUID(asset_id)))
    except ValueError:
        asset = None
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' was not found")
    return asset


SortOrder = Literal["risk", "cvss"]
SORT_QUERY = Query("risk", description="risk: contextual risk score first (unassessed last); "
                                       "cvss: known-exploited and highest CVSS first")


def _finding_list(session: Session, query, limit: int, offset: int, sort: SortOrder = "risk") -> FindingList:
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    order = [Cve.known_exploited.desc(), Cve.cvss_score.desc().nulls_last(), Finding.id]
    if sort == "risk":
        query = query.outerjoin(FindingRisk, FindingRisk.finding_id == Finding.id)
        order.insert(0, FindingRisk.score.desc().nulls_last())
    items = session.scalars(query.order_by(*order).limit(limit).offset(offset)).unique().all()
    return FindingList(total=total, limit=limit, offset=offset, items=items)


@router.get("/findings", response_model=FindingList, dependencies=[Depends(can_read)])
def list_findings(
    session: Session = Depends(get_session),
    severity: Severity | None = None,
    kev_only: bool = Query(False, alias="kev", description="Only CVEs in the CISA KEV catalogue"),
    finding_status: FindingStatus | None = Query(None, alias="status"),
    asset_id: str | None = None,
    cve: str | None = Query(None, max_length=30),
    q: str | None = Query(None, max_length=100,
                          description="Search: part of the CVE id, the software or the asset name"),
    unresolved: bool = Query(False, description="Only open or in-remediation findings"),
    active_assets: bool = Query(False, description="Only findings of active assets"),
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None = Query(
        None, description="Stored contextual risk level (Risk Engine)"),
    min_risk: int | None = Query(None, ge=0, le=100, description="Stored contextual risk score at least"),
    first_seen_from: date | None = Query(None, description="First detected on or after this UTC day"),
    first_seen_to: date | None = Query(None, description="First detected before this UTC day"),
    sort: SortOrder = SORT_QUERY,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Findings across all assets, highest contextual risk first (or `sort=cvss`)."""
    query = select(Finding).join(Finding.cve)
    if severity:
        query = query.where(Cve.severity == severity)
    if kev_only:
        query = query.where(Cve.known_exploited.is_(True))
    if finding_status:
        query = query.where(Finding.status == finding_status)
    if unresolved:
        query = query.where(Finding.status.in_((FindingStatus.OPEN, FindingStatus.IN_REMEDIATION)))
    if active_assets:
        query = query.where(Finding.asset_id.in_(select(Asset.id).where(Asset.status == LifecycleStatus.ACTIVE)))
    if risk_level or min_risk is not None:
        scored = select(FindingRisk.finding_id)
        if risk_level:
            scored = scored.where(FindingRisk.level == risk_level)
        if min_risk is not None:
            scored = scored.where(FindingRisk.score >= min_risk)
        query = query.where(Finding.id.in_(scored))
    if first_seen_from:
        query = query.where(Finding.first_seen >= datetime.combine(first_seen_from, time(), UTC))
    if first_seen_to:
        query = query.where(Finding.first_seen < datetime.combine(first_seen_to, time(), UTC))
    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
    if cve:
        query = query.where(Finding.cve_id == cve.strip().upper())
    if q and q.strip():
        like = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.where(or_(
            Finding.cve_id.ilike(like, escape="\\"), Finding.software.ilike(like, escape="\\"),
            Finding.asset_id.in_(select(Asset.id).where(Asset.name.ilike(like, escape="\\")))))
    return _finding_list(session, query, limit, offset, sort)


@router.get("/findings/{finding_id}", response_model=FindingRead, responses=NOT_FOUND,
            dependencies=[Depends(can_read)])
def get_finding(finding_id: int, session: Session = Depends(get_session)):
    try:
        return service.get_finding(session, finding_id)
    except service.NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/findings/{finding_id}", response_model=FindingRead, responses=NOT_FOUND)
def update_finding(finding_id: int, data: FindingUpdate, current: CurrentUser = Depends(can_write),
                   session: Session = Depends(get_session)):
    """Set status open / in_remediation / accepted_risk (a reason is required), or a ticket key."""
    try:
        return service.update_finding(session, current.ctx, finding_id, status=data.status,
                                      reason=data.reason, ticket_key=data.ticket_key)
    except service.NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except service.InvalidChange as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/assets/{asset_id}/findings", response_model=FindingList, responses=NOT_FOUND,
            dependencies=[Depends(can_read)])
def asset_findings(asset_id: str, session: Session = Depends(get_session),
                   finding_status: FindingStatus | None = Query(None, alias="status"),
                   sort: SortOrder = SORT_QUERY,
                   limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    asset = _asset(session, asset_id)
    query = select(Finding).join(Finding.cve).where(Finding.asset_id == asset.id)
    if finding_status:
        query = query.where(Finding.status == finding_status)
    return _finding_list(session, query, limit, offset, sort)


@router.get("/assets/{asset_id}/software", response_model=list[SoftwareRead], responses=NOT_FOUND,
            dependencies=[Depends(assets_read)])
def list_software(asset_id: str, session: Session = Depends(get_session)):
    """Manually entered software of an asset (scanned software is in the Monitoring results)."""
    return service.list_software(session, _asset(session, asset_id))


@router.post("/assets/{asset_id}/software", response_model=SoftwareRead, status_code=status.HTTP_201_CREATED,
             responses=NOT_FOUND)
def add_software(asset_id: str, data: SoftwareCreate, current: CurrentUser = Depends(assets_write),
                 session: Session = Depends(get_session)):
    return service.add_software(session, current.ctx, _asset(session, asset_id),
                                data.product, data.version, data.cpe)


@router.delete("/assets/{asset_id}/software/{software_id}", status_code=status.HTTP_204_NO_CONTENT,
               responses=NOT_FOUND)
def remove_software(asset_id: str, software_id: int, current: CurrentUser = Depends(assets_write),
                    session: Session = Depends(get_session)):
    try:
        service.remove_software(session, current.ctx, _asset(session, asset_id), software_id)
    except service.NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/correlation/run", response_model=CorrelationRunRead, status_code=status.HTTP_202_ACCEPTED,
             responses={409: {"description": "A correlation run is already queued or running"}})
def start_correlation(data: RunRequest | None = None, current: CurrentUser = Depends(can_write),
                      session: Session = Depends(get_session)):
    """Start correlation in the background (all active assets, or the given ids).

    Returns the queued run at once; follow it with GET /correlation/runs/{id}.
    """
    asset_ids = data.asset_ids if data else None
    try:
        run = queue_run(session, trigger="manual")
    except CorrelationBusy as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    audit.record_now(current.ctx, "correlation.run", target_type="correlation_run", target_id=str(run.id),
                     details={"assets": len(asset_ids) if asset_ids is not None else "all active"})
    jobs.run_in_background(jobs.execute_queued_run, run.id, asset_ids)
    return run


@router.get("/correlation/runs/{run_id}", response_model=CorrelationRunRead, responses=NOT_FOUND,
            dependencies=[Depends(can_read)])
def get_run(run_id: int, session: Session = Depends(get_session)):
    run = session.get(CorrelationRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Correlation run {run_id} was not found")
    return run


@router.get("/correlation/runs", response_model=list[CorrelationRunRead], dependencies=[Depends(can_read)])
def list_runs(limit: int = Query(20, ge=1, le=200), session: Session = Depends(get_session)):
    return session.scalars(select(CorrelationRun).order_by(CorrelationRun.id.desc()).limit(limit)).all()


@router.post("/correlation/kev/refresh")
def refresh_kev(current: CurrentUser = Depends(can_write), session: Session = Depends(get_session)):
    """Download the CISA KEV catalogue now (otherwise refreshed by the periodic job)."""
    try:
        count = kev.refresh(session)
    except kev.KevError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    audit.record_now(current.ctx, "correlation.kev_refresh", details={"entries": count})
    return {"kev_entries": count}


@router.get("/correlation/schedule", response_model=ScheduleStatus, dependencies=[Depends(can_read)])
def schedule_status(session: Session = Depends(get_session)):
    """Assessment schedule, the run in progress, the last finished run and data freshness."""
    from .. import config
    from ..monitoring.scheduler import get_scheduler
    scheduler = get_scheduler()
    job = scheduler.get_job(jobs.JOB_ID) if scheduler.running else None
    kev_sync = session.get(FeedSync, kev.FEED_NAME)
    runs = select(CorrelationRun).order_by(CorrelationRun.id.desc()).limit(1)
    return ScheduleStatus(
        periodic_enabled=config.CORRELATION_INTERVAL_HOURS > 0,
        interval_hours=config.CORRELATION_INTERVAL_HOURS,
        next_run_at=job.next_run_time if job else None,
        after_scan=config.CORRELATION_AFTER_SCAN,
        nvd_api_key_configured=bool(config.NVD_API_KEY),
        kev_last_synced=kev_sync.last_synced if kev_sync else None,
        kev_entries=kev_sync.item_count if kev_sync else None,
        kev_current=risk.kev_complete(session),
        active_run=session.scalars(runs.where(CorrelationRun.status.in_(ACTIVE_RUN_STATUSES))).first(),
        last_run=session.scalars(runs.where(CorrelationRun.status.not_in(ACTIVE_RUN_STATUSES))).first(),
    )

"""REST API for Jira tickets. Uses the existing permissions: reading needs `findings:read`,
creating / retrying / syncing a ticket needs `findings:write` (analyst, admin). The Jira
settings themselves come from the environment only and cannot be changed through the API.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth.dependencies import CurrentUser, get_current_user, require
from ..auth.permissions import Permission
from ..database import get_session
from . import jobs, service
from .jira import JiraError
from .schemas import IntegrationStatus, TicketRead, TicketRequestResult

router = APIRouter(tags=["jira tickets"], dependencies=[Depends(get_current_user)])

can_read = require(Permission.FINDINGS_READ)
can_write = require(Permission.FINDINGS_WRITE)
NOT_FOUND: dict[int | str, dict[str, Any]] = {404: {"description": "Not found"}}
UNAVAILABLE: dict[int | str, dict[str, Any]] = {409: {"description": "Jira integration disabled or misconfigured, or the finding is not eligible"}}


@router.get("/integrations/jira", response_model=IntegrationStatus, dependencies=[Depends(can_read)])
def jira_status(session: Session = Depends(get_session)):
    """Whether ticket creation is enabled, the qualification policy and the delivery queue."""
    return service.integration_status(session)


@router.get("/findings/{finding_id}/ticket", response_model=TicketRead, responses=NOT_FOUND,
            dependencies=[Depends(can_read)])
def get_ticket(finding_id: int, session: Session = Depends(get_session)):
    ticket = service.get_ticket(session, finding_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="No Jira ticket for this finding")
    return ticket


@router.post("/findings/{finding_id}/ticket", response_model=TicketRequestResult,
             status_code=status.HTTP_202_ACCEPTED, responses={**NOT_FOUND, **UNAVAILABLE})
def request_ticket(finding_id: int, current: CurrentUser = Depends(can_write),
                   session: Session = Depends(get_session)):
    """Create a Jira task for a finding, or retry a failed one. Uses the same base checks,
    persistence and duplicate prevention as automatic creation (the severity threshold is the
    analyst's decision). Delivery happens in the background; poll GET .../ticket."""
    try:
        ticket, queued = service.request_ticket(session, current.ctx, finding_id)
    except service.Unavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except service.NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except service.NotEligible as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if queued:
        jobs.dispatch()
    session.refresh(ticket)
    return TicketRequestResult(queued=queued, ticket=TicketRead.model_validate(ticket))


@router.post("/findings/{finding_id}/ticket/sync", response_model=TicketRead,
             responses={**NOT_FOUND, **UNAVAILABLE, 502: {"description": "Jira request failed"}},
             dependencies=[Depends(can_write)])
def sync_ticket(finding_id: int, session: Session = Depends(get_session)):
    """Read the issue's current status from Jira (read-only; Jira statuses are not mapped onto findings)."""
    try:
        return service.refresh_status(session, service.client(), finding_id)
    except service.Unavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except service.NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except JiraError as exc:
        raise HTTPException(status_code=502, detail=f"Jira request failed: {exc}") from exc

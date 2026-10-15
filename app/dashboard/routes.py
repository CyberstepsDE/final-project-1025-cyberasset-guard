"""REST API for the executive dashboard.

One summary endpoint; it needs `findings:read` (vulnerability data) and `assets:read`
(asset names in the top risks) - every role has both today, the check keeps it explicit.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..auth.dependencies import get_current_user, require
from ..auth.permissions import Permission
from ..correlation import routes as correlation_routes
from ..database import get_session, utcnow
from . import service

router = APIRouter(tags=["dashboard"], dependencies=[Depends(get_current_user)])


@router.get("/dashboard", dependencies=[Depends(require(Permission.FINDINGS_READ)),
                                        Depends(require(Permission.ASSETS_READ))])
def dashboard(month: str | None = Query(None, max_length=7, description="YYYY-MM (UTC); default: current month"),
              session: Session = Depends(get_session)):
    """Executive security summary: posture, monthly figures, trends, top risks, assessment health."""
    now = utcnow()
    try:
        year, mon = service.parse_month(month, now)
    except service.InvalidPeriod as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    schedule = correlation_routes.schedule_status(session).model_dump()      # reuse, no second source
    return service.summary(session, year, mon, schedule, now)

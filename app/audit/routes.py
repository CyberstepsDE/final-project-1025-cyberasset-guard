"""Read-only audit log API (administrators). There is deliberately no write/delete endpoint."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ..auth.dependencies import CurrentUser, require
from ..auth.permissions import Permission
from ..database import get_session
from . import service
from .models import Outcome

router = APIRouter(prefix="/audit", tags=["audit log"])


class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    occurred_at: datetime
    actor_user_id: str | None
    actor_username: str | None
    ip_address: str | None
    action: str
    outcome: Outcome
    target_type: str | None
    target_id: str | None
    target_label: str | None
    details: dict[str, Any] | None


class AuditEventList(BaseModel):
    items: list[AuditEventRead]
    total: int
    limit: int
    offset: int


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


@router.get("", response_model=AuditEventList)
def list_events(
    _: CurrentUser = Depends(require(Permission.AUDIT_READ)),
    session: Session = Depends(get_session),
    action: str | None = Query(None, max_length=64, description="Exact action, or prefix ending in '*' (auth.*)"),
    actor: str | None = Query(None, max_length=64, description="Username"),
    outcome: Outcome | None = None,
    target_type: str | None = Query(None, max_length=32),
    target_id: str | None = Query(None, max_length=64),
    since: datetime | None = Query(None, description="ISO 8601; naive values are treated as UTC"),
    until: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Audit events, newest first."""
    filters = service.AuditFilter(action=action, actor=actor, outcome=outcome, target_type=target_type,
                                  target_id=target_id, since=_utc(since), until=_utc(until))
    items, total = service.query(session, filters, limit, offset)
    return AuditEventList(items=items, total=total, limit=limit, offset=offset)

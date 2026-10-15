"""Writing and querying audit events.

`record()` adds the event to the caller's session, so it is committed in the
same transaction as the change it describes (no change without its audit entry).
`record_now()` commits on its own - used where there is no business transaction
(failed logins, access denied).
"""
from __future__ import annotations

import logging
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import database
from ..database import utcnow
from .models import AuditEvent, Outcome

log = logging.getLogger(__name__)

MAX_VALUE_LENGTH = 500          # long free-text values are truncated in details
SENSITIVE_KEYS = {"password", "current_password", "new_password", "password_hash", "token"}


@dataclass(frozen=True)
class AuditContext:
    """Who is acting, from where. Built per request by the auth dependencies."""

    user_id: str | None
    username: str | None
    ip_address: str | None


SYSTEM = AuditContext(user_id=None, username="system", ip_address=None)


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[redacted]" if k in SENSITIVE_KEYS else _clean(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, str) and len(value) > MAX_VALUE_LENGTH:
        return value[:MAX_VALUE_LENGTH] + "…"
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _event(ctx: AuditContext, action: str, outcome: Outcome, target_type: str | None,
           target_id: str | None, target_label: str | None, details: dict | None) -> AuditEvent:
    return AuditEvent(
        occurred_at=utcnow(), actor_user_id=ctx.user_id, actor_username=ctx.username,
        ip_address=ctx.ip_address, action=action, outcome=outcome, target_type=target_type,
        target_id=target_id, target_label=(target_label or None) and target_label[:200],
        details=_clean(details) if details else None)


def record(session: Session, ctx: AuditContext, action: str, *, outcome: Outcome = Outcome.SUCCESS,
           target_type: str | None = None, target_id: str | None = None,
           target_label: str | None = None, details: dict | None = None) -> None:
    session.add(_event(ctx, action, outcome, target_type, target_id, target_label, details))


def record_now(ctx: AuditContext, action: str, **kwargs) -> None:
    """Commit an audit event in its own transaction. Never raises into the caller."""
    try:
        session = next(database.get_session())
        try:
            record(session, ctx, action, **kwargs)
            session.commit()
        finally:
            session.close()
    except Exception:  # noqa: BLE001 - an audit write failure must not break the request
        log.exception("could not write audit event %s", action)


def diff(before: dict[str, Any], after: dict[str, Any], ignore: Collection[str] = frozenset()) -> dict:
    """{field: {"from": old, "to": new}} for every field that changed."""
    return {k: {"from": before.get(k), "to": after.get(k)}
            for k in sorted(set(before) | set(after))
            if k not in ignore and before.get(k) != after.get(k)}


@dataclass
class AuditFilter:
    action: str | None = None          # exact, or prefix with trailing '*' (e.g. "auth.*")
    actor: str | None = None
    outcome: Outcome | None = None
    target_type: str | None = None
    target_id: str | None = None
    since: datetime | None = None
    until: datetime | None = None


def query(session: Session, f: AuditFilter, limit: int = 100, offset: int = 0) -> tuple[list[AuditEvent], int]:
    stmt = select(AuditEvent)
    if f.action:
        if f.action.endswith("*"):
            prefix = f.action[:-1].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            stmt = stmt.where(AuditEvent.action.like(prefix + "%", escape="\\"))
        else:
            stmt = stmt.where(AuditEvent.action == f.action)
    if f.actor:
        stmt = stmt.where(AuditEvent.actor_username == f.actor.strip().lower())
    if f.outcome:
        stmt = stmt.where(AuditEvent.outcome == f.outcome)
    if f.target_type:
        stmt = stmt.where(AuditEvent.target_type == f.target_type)
    if f.target_id:
        stmt = stmt.where(AuditEvent.target_id == f.target_id)
    if f.since:
        stmt = stmt.where(AuditEvent.occurred_at >= f.since)
    if f.until:
        stmt = stmt.where(AuditEvent.occurred_at <= f.until)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = session.scalars(stmt.order_by(AuditEvent.id.desc()).limit(limit).offset(offset)).all()
    return list(rows), total

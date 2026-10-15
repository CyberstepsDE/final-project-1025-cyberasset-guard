"""Audit log entries (append-only).

Actor and target are stored *denormalized* (username, label) so an entry stays
meaningful even if the user or asset is renamed later. Database triggers reject
UPDATE and DELETE, so entries cannot be altered through the application.
"""
from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from sqlalchemy import DDL, JSON, Enum, Index, Integer, String, event
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base, UTCDateTime, utcnow


class Outcome(str, enum.Enum):
    SUCCESS = "success"
    FAILURE = "failure"      # e.g. wrong password, validation error
    DENIED = "denied"        # authenticated, but not permitted


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    actor_user_id: Mapped[str | None] = mapped_column(String(36))
    actor_username: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    action: Mapped[str] = mapped_column(String(64), nullable=False)       # e.g. asset.update
    outcome: Mapped[Outcome] = mapped_column(
        Enum(Outcome, native_enum=False, create_constraint=True, validate_strings=True, length=16,
             values_callable=lambda e: [m.value for m in e], name="ck_audit_outcome"),
        nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(32))           # asset | user | scan ...
    target_id: Mapped[str | None] = mapped_column(String(64))
    target_label: Mapped[str | None] = mapped_column(String(200))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    __table_args__ = (
        Index("ix_audit_events_occurred_at", "occurred_at"),
        Index("ix_audit_events_action", "action"),
        Index("ix_audit_events_actor", "actor_username"),
        Index("ix_audit_events_target", "target_type", "target_id"),
    )


for _op in ("UPDATE", "DELETE"):
    event.listen(AuditEvent.__table__, "after_create", DDL(
        f"CREATE TRIGGER IF NOT EXISTS audit_events_no_{_op.lower()} BEFORE {_op} ON audit_events "
        f"BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END").execute_if(dialect="sqlite"))

# PostgreSQL: same guarantee, plus TRUNCATE (which bypasses row triggers).
for _ddl in (
    "CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger LANGUAGE plpgsql AS "
    "$$ BEGIN RAISE EXCEPTION 'audit_events is append-only'; END $$",
    "CREATE TRIGGER audit_events_no_update_delete BEFORE UPDATE OR DELETE ON audit_events "
    "FOR EACH ROW EXECUTE FUNCTION audit_events_append_only()",
    "CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events "
    "FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only()",
):
    event.listen(AuditEvent.__table__, "after_create", DDL(_ddl).execute_if(dialect="postgresql"))

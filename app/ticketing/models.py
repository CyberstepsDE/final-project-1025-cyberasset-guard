"""Persistent Jira ticket record per finding: idempotency anchor and delivery queue (outbox).

One row per finding (UNIQUE finding_id), created in the database before Jira is ever
called. The row carries the delivery state, so a ticket survives restarts, is retried
with backoff, and two workers or two assessment runs can never create two issues for
the same finding.

States:
  pending   queued, waiting for the worker (next_attempt_at)
  sending   claimed by a worker until lease_until (an expired lease is reclaimed)
  failed    temporary error (timeout, 429, 5xx); retried at next_attempt_at
  error     permanent error (400/401/403/404, configuration) or attempts exhausted;
            only a manual retry re-queues it
  created   the Jira issue exists (issue_key / issue_url)
  skipped   an automatic ticket was no longer needed when it was due (finding closed,
            accepted, or no longer qualifying)
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base, UTCDateTime, utcnow

STATES = ("pending", "sending", "failed", "error", "created", "skipped")
DUE_STATES = ("pending", "failed")


class JiraTicket(Base):
    __tablename__ = "jira_tickets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False,
                                            unique=True)
    # Random label put on the Jira issue; searching for it resolves an ambiguous outcome
    # (timeout after Jira may already have created the issue). Unique across installations.
    label: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(String(10), nullable=False, default="pending")
    trigger: Mapped[str] = mapped_column(String(10), nullable=False)       # auto / manual
    requested_by: Mapped[str | None] = mapped_column(String(100))
    issue_key: Mapped[str | None] = mapped_column(String(50))
    issue_url: Mapped[str | None] = mapped_column(String(300))
    jira_status: Mapped[str | None] = mapped_column(String(100))            # last known Jira status
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    lease_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_error: Mapped[str | None] = mapped_column(Text)                   # sanitised, never credentials
    # authentication / permission / invalid_project / invalid_request / rate_limited / network /
    # timeout / server / malformed / config
    error_category: Mapped[str | None] = mapped_column(String(20))
    # Verification note (finding resolved / reopened) waiting to be added as a Jira comment.
    note_pending: Mapped[str | None] = mapped_column(Text)
    note_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow)
    synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime)        # last successful Jira call

    __table_args__ = (Index("ix_jira_tickets_state", "state"),)

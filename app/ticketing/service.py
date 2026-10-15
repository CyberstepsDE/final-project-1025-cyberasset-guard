"""Jira ticket delivery for qualifying findings (outbox pattern).

Flow: correlation + risk scoring persist the finding -> enqueue_qualifying() inserts a
`jira_tickets` row (state pending) in the database -> the worker (jobs.deliver, on the
existing APScheduler) claims due rows and talks to Jira. Detection never waits for Jira
and a Jira outage never changes or removes a finding.

Duplicate prevention
  * UNIQUE(finding_id): one ticket row per finding, ever. Concurrent enqueues of the same
    finding lose on the constraint and reuse the existing row; a reopened finding keeps
    its issue.
  * Claiming is a conditional UPDATE (state due -> sending, with a lease) checked by
    rowcount, so only one worker - in any process - sends a given row. A lease left by a
    crashed worker expires and the row is picked up again (restart recovery).
  * Every attempt first searches Jira for the row's unique label and adopts an issue it
    finds. A create whose answer was lost (timeout, 5xx, unreadable body) therefore never
    produces a second issue on the retry. Residual window: Jira's search index can lag a
    few seconds behind a create; the first retry waits at least a minute.

Failures
  * temporary (timeout, connection, 429, 5xx): state failed, retried with exponential
    backoff (Retry-After honoured) up to CAG_JIRA_MAX_ATTEMPTS, then error;
  * permanent (400/401/403/404, invalid configuration): state error at once;
  * error rows are only re-queued by an analyst (POST /findings/{id}/ticket) and are
    listed in GET /integrations/jira. Failures are audit-logged; messages never contain
    credentials.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta
from typing import cast

from sqlalchemy import CursorResult, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import config
from ..assets.models import Asset, LifecycleStatus
from ..audit import service as audit
from ..audit.models import Outcome
from ..correlation.models import Finding
from ..database import utcnow
from ..risk.models import FindingRisk
from . import content
from .jira import JiraClient, JiraConfigError, JiraError, JiraPermanent, JiraSettings, build_settings
from .models import DUE_STATES, JiraTicket
from .policy import Policy, qualifies

log = logging.getLogger(__name__)

LEASE = timedelta(minutes=5)
BATCH = 25
MAX_BACKOFF = timedelta(hours=6)
MAX_NOTE_ATTEMPTS = 5


class Unavailable(RuntimeError):
    """The integration is disabled or misconfigured."""


class NotFound(LookupError):
    pass


class NotEligible(ValueError):
    """The finding fails the base qualification checks (closed, accepted, inactive asset ...)."""


def max_attempts() -> int:
    return 1 + config.JIRA_MAX_RETRIES


# --- configuration -------------------------------------------------------------------------------

def settings() -> JiraSettings:
    """Validated settings; raises Unavailable (disabled) or JiraConfigError (misconfigured)."""
    if not config.JIRA_ENABLED:
        raise Unavailable("Jira integration is disabled (CAG_JIRA_ENABLED=false)")
    return build_settings(config.JIRA_BASE_URL, config.JIRA_PROJECT_KEY, config.JIRA_EMAIL,
                          config.JIRA_API_TOKEN, config.JIRA_ISSUE_TYPE, config.JIRA_DEFAULT_ASSIGNEE,
                          config.JIRA_LABEL, config.JIRA_TIMEOUT_SECONDS)


def state() -> tuple[str, str | None]:
    """('disabled' | 'misconfigured' | 'enabled', problem)."""
    try:
        settings()
    except Unavailable:
        return "disabled", None
    except JiraConfigError as exc:
        return "misconfigured", str(exc)
    return "enabled", None


def client(fetch=None) -> JiraClient:
    """A client for the configured site; raises Unavailable with the reason otherwise."""
    try:
        s = settings()
    except JiraConfigError as exc:
        raise Unavailable(f"Jira integration is misconfigured: {exc}") from None
    return JiraClient(s, fetch) if fetch else JiraClient(s)


def integration_status(session: Session) -> dict:
    current, problem = state()
    counts = dict(session.execute(select(JiraTicket.state, func.count()).group_by(JiraTicket.state)).all())
    last_error = session.scalar(select(JiraTicket.last_error).where(JiraTicket.state.in_(("failed", "error")))
                                .order_by(JiraTicket.updated_at.desc()).limit(1))
    return {"state": current, "problem": problem,
            "base_url": config.JIRA_BASE_URL or None if current != "disabled" else None,
            "project_key": config.JIRA_PROJECT_KEY or None, "issue_type": config.JIRA_ISSUE_TYPE,
            "label": config.JIRA_LABEL, "max_retries": config.JIRA_MAX_RETRIES,
            "policy": Policy.from_config().describe(),
            "tickets": {s: counts.get(s, 0) for s in ("pending", "sending", "failed", "error", "created", "skipped")},
            "last_error": last_error}


# --- qualification + queue -----------------------------------------------------------------------

def _decision(finding: Finding, policy: Policy, manual: bool = False, own_key: str | None = None) -> tuple[bool, str]:
    risk = finding.risk
    linked_by_hand = bool(finding.ticket_key) and finding.ticket_key != own_key
    return qualifies(policy, status=finding.status.value, asset_active=finding.asset.status == LifecycleStatus.ACTIVE,
                     level=risk.level if risk else None, confidence=finding.confidence,
                     has_manual_ticket=linked_by_hand, manual=manual)


def eligibility(finding: Finding) -> dict:
    """For the UI: may a task be created automatically / by hand, and why (not)."""
    policy = Policy.from_config()
    auto, auto_reason = _decision(finding, policy)
    manual, manual_reason = _decision(finding, policy, manual=True)
    return {"automatic": auto, "manual": manual, "reason": auto_reason if auto or not manual else
            f"{auto_reason}; an analyst can still create a task", "manual_reason": None if manual else manual_reason}


def _new_ticket(session: Session, finding_id: int, trigger: str, requested_by: str | None) -> JiraTicket | None:
    """Insert the row; None when another transaction inserted one first (UNIQUE finding_id)."""
    ticket = JiraTicket(finding_id=finding_id, label=f"cag-{secrets.token_hex(8)}", state="pending",
                        trigger=trigger, requested_by=requested_by, next_attempt_at=utcnow())
    try:
        with session.begin_nested():
            session.add(ticket)
    except IntegrityError:
        return None
    return ticket


def enqueue_qualifying(session: Session, asset_ids: list[str] | None = None, policy: Policy | None = None) -> int:
    """Queue a ticket for every qualifying finding without one (or whose automatic ticket was
    skipped earlier and now qualifies again). Database only - no Jira call."""
    if state()[0] != "enabled":
        return 0
    policy = policy or Policy.from_config()
    query = (select(Finding, JiraTicket).join(Asset, Asset.id == Finding.asset_id)
             .join(FindingRisk, FindingRisk.finding_id == Finding.id)
             .outerjoin(JiraTicket, JiraTicket.finding_id == Finding.id)
             .where(or_(JiraTicket.id.is_(None), JiraTicket.state == "skipped"), Finding.ticket_key.is_(None),
                    Finding.status.in_(("open", "in_remediation")), Asset.status == LifecycleStatus.ACTIVE))
    if asset_ids is not None:
        query = query.where(Finding.asset_id.in_(asset_ids))
    queued = 0
    for finding, ticket in session.execute(query).unique().all():
        if not _decision(finding, policy)[0]:
            continue
        if ticket is None:
            queued += _new_ticket(session, finding.id, "auto", None) is not None
        else:                                             # skipped before, qualifies again
            ticket.state, ticket.trigger, ticket.attempts = "pending", "auto", 0
            ticket.next_attempt_at, ticket.last_error = utcnow(), None
            queued += 1
    session.commit()
    return queued


def get_ticket(session: Session, finding_id: int) -> JiraTicket | None:
    return session.scalar(select(JiraTicket).where(JiraTicket.finding_id == finding_id))


def request_ticket(session: Session, ctx: audit.AuditContext, finding_id: int) -> tuple[JiraTicket, bool]:
    """Analyst: create a ticket for a finding, or re-queue a failed/skipped one.
    Returns (ticket, queued); queued is False when the issue already exists or is in flight."""
    if state()[0] != "enabled":
        _raise_unavailable()
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise NotFound(f"Finding {finding_id} was not found")
    label = f"{finding.cve_id} on {finding.asset.name}"
    ticket = get_ticket(session, finding_id)
    if ticket is None or ticket.state != "created":
        ok, reason = _decision(finding, Policy.from_config(), manual=True)
        if not ok:
            raise NotEligible(f"No Jira task can be created: {reason}")
    if ticket is None:
        ticket = _new_ticket(session, finding_id, "manual", ctx.username)
        if ticket is not None:
            audit.record(session, ctx, "jira.ticket_requested", target_type="finding", target_id=str(finding_id),
                         target_label=label)
            session.commit()
            return ticket, True
        ticket = get_ticket(session, finding_id)          # a concurrent request inserted it first
        assert ticket is not None  # noqa: S101
    if ticket.state in ("created", "pending", "sending"):
        return ticket, False
    before = ticket.state                                # failed / error / skipped -> queue again
    ticket.state, ticket.trigger, ticket.requested_by = "pending", "manual", ctx.username
    ticket.attempts, ticket.next_attempt_at, ticket.lease_until = 0, utcnow(), None
    audit.record(session, ctx, "jira.ticket_retry", target_type="finding", target_id=str(finding_id),
                 target_label=label, details={"previous_state": before, "last_error": ticket.last_error})
    session.commit()
    return ticket, True


def _raise_unavailable() -> None:
    current, problem = state()
    raise Unavailable("Jira integration is disabled" if current == "disabled"
                      else f"Jira integration is misconfigured: {problem}")


def add_note(session: Session, finding: Finding, text: str) -> None:
    """Queue a verification note (finding closed / reopened) for the finding's Jira issue.
    Called inside the correlation transaction; delivered by the worker."""
    ticket = get_ticket(session, finding.id) if finding.id else None
    if ticket is None or ticket.state != "created":
        return
    ticket.note_pending = (f"{ticket.note_pending}\n" if ticket.note_pending else "") + text
    ticket.note_attempts = 0


# --- delivery ------------------------------------------------------------------------------------

def _backoff(attempts: int, retry_after: float | None) -> timedelta:
    delay = min(timedelta(minutes=2 ** max(attempts - 1, 0)), MAX_BACKOFF)
    if retry_after:
        delay = max(delay, timedelta(seconds=retry_after))
    return delay


def _claim(session: Session, ticket_id: int, now: datetime) -> bool:
    """Atomically take a due row (or one whose lease expired). Exactly one caller wins."""
    result = cast(CursorResult, session.execute(
        update(JiraTicket)
        .where(JiraTicket.id == ticket_id,
               or_(JiraTicket.state.in_(DUE_STATES) & or_(JiraTicket.next_attempt_at.is_(None),
                                                          JiraTicket.next_attempt_at <= now),
                   (JiraTicket.state == "sending") & (JiraTicket.lease_until < now)))
        .values(state="sending", lease_until=now + LEASE, attempts=JiraTicket.attempts + 1,
                last_attempt_at=now, updated_at=now)
        .execution_options(synchronize_session=False)))
    session.commit()
    return result.rowcount == 1


def _due_ids(session: Session, now: datetime, limit: int) -> list[int]:
    return list(session.scalars(
        select(JiraTicket.id).where(or_(
            JiraTicket.state.in_(DUE_STATES) & or_(JiraTicket.next_attempt_at.is_(None),
                                                   JiraTicket.next_attempt_at <= now),
            (JiraTicket.state == "sending") & (JiraTicket.lease_until < now)))
        .order_by(JiraTicket.id).limit(limit)))


def _label(finding: Finding) -> str:
    return f"{finding.cve_id} on {finding.asset.name}"


def _fail(session: Session, ticket: JiraTicket, finding: Finding, exc: JiraError, now: datetime) -> None:
    message = str(exc)[:500]
    ticket.last_error, ticket.error_category, ticket.lease_until = message, exc.category, None
    permanent = isinstance(exc, JiraPermanent)
    if permanent or ticket.attempts >= max_attempts():
        ticket.state, ticket.next_attempt_at = "error", None
        audit.record(session, audit.SYSTEM, "jira.ticket_failed", outcome=Outcome.FAILURE, target_type="finding",
                     target_id=str(finding.id), target_label=_label(finding),
                     details={"error": message, "category": exc.category, "attempts": ticket.attempts,
                              "reason": "permanent error" if permanent else "attempts exhausted"})
        log.error("Jira ticket for finding %s failed: %s", finding.id, message)
    else:
        ticket.state, ticket.next_attempt_at = "failed", now + _backoff(ticket.attempts, exc.retry_after)
        log.warning("Jira ticket for finding %s: attempt %d failed, retrying at %s: %s", finding.id,
                    ticket.attempts, ticket.next_attempt_at.isoformat(timespec="seconds"), message)


def _deliver_one(session: Session, jira: JiraClient, ticket: JiraTicket, policy: Policy, now: datetime,
                 meta: dict) -> str:
    finding = session.get(Finding, ticket.finding_id)
    if finding is None:                                   # finding rows are never deleted; defensive
        ticket.state, ticket.last_error = "skipped", "finding no longer exists"
        session.commit()
        return "skipped"
    ok, reason = _decision(finding, policy, manual=ticket.trigger == "manual")
    if not ok:                                            # e.g. accepted or fixed before delivery
        ticket.state, ticket.lease_until, ticket.last_error = "skipped", None, f"not created: {reason}"
        session.commit()
        return "skipped"
    try:
        key = jira.find_by_label(ticket.label)            # idempotency: adopt an issue we created before
        adopted = key is not None
        if key is None:
            if "project" not in meta:                     # project + issue type check, once per run
                meta["project"] = jira.metadata()
            key = jira.create_issue(content.fields(finding, ticket.label, jira.settings, meta["project"]))
    except JiraError as exc:
        _fail(session, ticket, finding, exc, now)
        session.commit()
        return ticket.state
    ticket.state, ticket.issue_key, ticket.issue_url = "created", key, jira.issue_url(key)
    ticket.lease_until, ticket.next_attempt_at, ticket.synced_at = None, None, now
    ticket.last_error = ticket.error_category = None
    linked = finding.ticket_key is None
    if linked:
        finding.ticket_key = key                          # closes as verified_fixed later (engine)
    audit.record(session, audit.SYSTEM if ticket.trigger == "auto" else
                 audit.AuditContext(user_id=None, username=ticket.requested_by or "system", ip_address=None),
                 "jira.ticket_created", target_type="finding", target_id=str(finding.id),
                 target_label=_label(finding),
                 details={"issue_key": key, "trigger": ticket.trigger, "attempts": ticket.attempts,
                          "adopted_existing_issue": adopted, "linked_to_finding": linked})
    session.commit()
    log.info("Jira issue %s %s for finding %s", key, "adopted" if adopted else "created", finding.id)
    return "created"


def _deliver_note(session: Session, jira: JiraClient, ticket: JiraTicket, now: datetime) -> None:
    claimed = cast(CursorResult, session.execute(
        update(JiraTicket).where(JiraTicket.id == ticket.id, JiraTicket.state == "created",
                                 JiraTicket.note_pending.is_not(None),
                                 or_(JiraTicket.lease_until.is_(None), JiraTicket.lease_until < now))
        .values(lease_until=now + LEASE).execution_options(synchronize_session=False))).rowcount
    session.commit()
    if claimed != 1:
        return
    session.refresh(ticket)
    text = ticket.note_pending
    if not text or not ticket.issue_key:
        return
    try:
        jira.add_comment(ticket.issue_key, content.note(f"CyberAsset Guard: {text}"))
    except JiraError as exc:
        ticket.note_attempts += 1
        ticket.last_error, ticket.lease_until = f"note: {str(exc)[:480]}", None
        if isinstance(exc, JiraPermanent) or ticket.note_attempts >= MAX_NOTE_ATTEMPTS:
            ticket.note_pending = None                    # give up on this note; visible in last_error
            log.error("Jira note for %s dropped: %s", ticket.issue_key, exc)
        session.commit()
        return
    # A note queued while the comment was being sent stays pending.
    rest = ticket.note_pending[len(text):].lstrip("\n") if ticket.note_pending else ""
    ticket.note_pending, ticket.note_attempts, ticket.lease_until, ticket.synced_at = rest or None, 0, None, now
    session.commit()


def deliver_due(session: Session, jira: JiraClient, now: datetime | None = None, limit: int = BATCH) -> dict:
    """Process due tickets and notes. Returns counts per outcome."""
    now = now or utcnow()
    policy = Policy.from_config()
    outcome: dict[str, int] = {}
    meta: dict = {}
    for ticket_id in _due_ids(session, now, limit):
        if not _claim(session, ticket_id, now):
            continue                                      # another worker took it
        ticket = session.get(JiraTicket, ticket_id)
        if ticket is None:
            continue
        session.refresh(ticket)
        result = _deliver_one(session, jira, ticket, policy, now, meta)
        outcome[result] = outcome.get(result, 0) + 1
    for ticket in session.scalars(select(JiraTicket).where(JiraTicket.state == "created",
                                                           JiraTicket.note_pending.is_not(None)).limit(limit)):
        _deliver_note(session, jira, ticket, now)
    return outcome


def refresh_status(session: Session, jira: JiraClient, finding_id: int) -> JiraTicket:
    """Read the issue's current Jira status (read-only; Jira statuses are not mapped onto findings)."""
    ticket = get_ticket(session, finding_id)
    if ticket is None or not ticket.issue_key:
        raise NotFound("No Jira issue exists for this finding yet")
    ticket.jira_status = jira.get_status(ticket.issue_key)
    ticket.synced_at = utcnow()
    session.commit()
    return ticket

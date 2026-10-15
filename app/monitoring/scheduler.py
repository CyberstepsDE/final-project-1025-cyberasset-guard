"""Part 4 — scheduled scans.

Runs discovery/port/version scans automatically on a recurring interval using
APScheduler's BackgroundScheduler. Schedules are persisted in the `schedules`
table so they survive restarts: the FastAPI app reloads and re-registers every
enabled schedule on startup (see app.main).

Each job opens its own short-lived SQLAlchemy session (see database.session_scope),
so jobs running on scheduler threads never share a session across threads.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from .. import config
from ..database import session_scope
from . import service
from . import targets as target_policy
from .models import Schedule, as_dict

log = logging.getLogger(__name__)

# Map a schedule's scan_type to the service runner that executes it.
SCAN_RUNNERS = {
    "discovery": lambda target, ports: service.run_discovery(target),
    "port": lambda target, ports: service.run_port_scan(target, ports),
    "version": lambda target, ports: service.run_version_scan(target, ports),
}

_scheduler: BackgroundScheduler | None = None


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _job_id(schedule_id: int) -> str:
    return f"schedule-{schedule_id}"


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(daemon=True)
    return _scheduler


# --- job execution ----------------------------------------------------------

def _run_scheduled(schedule_id: int) -> None:
    """Execute one scheduled scan and record the outcome on the schedule row."""
    with session_scope() as session:
        sched = session.get(Schedule, schedule_id)
        run = (sched.scan_type, sched.target, sched.ports) if sched and sched.enabled else None
    if run is None:
        return  # schedule was removed or disabled

    scan_type, target, ports = run
    runner = SCAN_RUNNERS.get(scan_type)
    if runner is None:
        return

    try:
        scan_id = runner(target, ports)
    except Exception as exc:  # noqa: BLE001 - record any scan failure, keep running
        with session_scope() as session:
            sched = session.get(Schedule, schedule_id)
            if sched is not None:
                sched.last_run_at, sched.last_error = _now(), str(exc)
        return

    with session_scope() as session:
        sched = session.get(Schedule, schedule_id)
        if sched is not None:
            sched.last_run_at, sched.last_scan_id, sched.last_error = _now(), scan_id, None


def _add_job(schedule_id: int, interval_seconds: int, run_now: bool = True) -> None:
    """Register (or replace) the APScheduler job for a schedule."""
    sched = get_scheduler()
    kwargs = {}
    if run_now:
        # Kick off a first run immediately, then repeat every interval.
        kwargs["next_run_time"] = datetime.now()
    sched.add_job(
        _run_scheduled,
        trigger="interval",
        seconds=interval_seconds,
        args=[schedule_id],
        id=_job_id(schedule_id),
        replace_existing=True,
        **kwargs,
    )


# --- lifecycle --------------------------------------------------------------

def start() -> None:
    """Start the scheduler and register every enabled schedule from the DB."""
    sched = get_scheduler()
    if not sched.running:
        sched.start()
    with session_scope() as session:
        rows = [(s.id, s.target, s.ports, s.interval_seconds)
                for s in session.scalars(select(Schedule).where(Schedule.enabled == 1)).all()]
    for schedule_id, target, ports, interval_seconds in rows:
        problem = _schedule_problem(target, ports, interval_seconds)
        if problem:
            # Schedules stored before target validation existed may be unsafe: disable, never run them.
            with session_scope() as session:
                s = session.get(Schedule, schedule_id)
                s.enabled, s.last_error = 0, f"disabled at startup: {problem}"
            log.warning("scan schedule %s disabled: %s", schedule_id, problem)
            continue
        # On startup, don't double-fire past-due runs — wait one interval.
        _add_job(schedule_id, interval_seconds, run_now=False)


def _schedule_problem(target: str, ports: str | None, interval_seconds: int) -> str | None:
    """Why a schedule must not run, or None. DNS failures are tolerated (may be transient)."""
    if interval_seconds < config.SCAN_MIN_INTERVAL_SECONDS:
        return f"interval {interval_seconds}s is below CAG_SCAN_MIN_INTERVAL_SECONDS ({config.SCAN_MIN_INTERVAL_SECONDS}s)"
    try:
        target_policy.prepare(target)
        target_policy.validate_ports(ports)
    except target_policy.TargetUnresolvable:
        return None
    except (target_policy.TargetError, target_policy.TargetNotAllowed) as exc:
        return str(exc)
    return None


def shutdown() -> None:
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        _scheduler.shutdown(wait=False)


# --- schedule management (used by API and CLI) ------------------------------

def add_schedule(scan_type: str, target: str, interval_seconds: int,
                 ports: str | None = None) -> dict:
    """Create a recurring scan schedule. Returns the stored schedule."""
    if scan_type not in SCAN_RUNNERS:
        raise ValueError(f"unknown scan_type '{scan_type}' (expected one of {list(SCAN_RUNNERS)})")
    if interval_seconds < config.SCAN_MIN_INTERVAL_SECONDS:
        raise ValueError(f"interval_seconds must be at least {config.SCAN_MIN_INTERVAL_SECONDS} "
                         "(CAG_SCAN_MIN_INTERVAL_SECONDS)")
    try:
        target_policy.prepare(target)
        ports = target_policy.validate_ports(ports)
    except (target_policy.TargetError, target_policy.TargetNotAllowed) as exc:
        raise ValueError(str(exc)) from None

    with session_scope() as session:
        sched = Schedule(scan_type=scan_type, target=target, ports=ports,
                         interval_seconds=interval_seconds, enabled=1, created_at=_now())
        session.add(sched)
        session.flush()
        schedule_id = sched.id

    # Register the live job only when the scheduler is actually running
    # (e.g. inside the server). From the CLI the row simply persists and the
    # server picks it up on its next startup.
    if get_scheduler().running:
        _add_job(schedule_id, interval_seconds)
    return get_schedule(schedule_id)


def remove_schedule(schedule_id: int) -> bool:
    """Remove a schedule and its job. Returns True if a row was deleted."""
    sched = get_scheduler()
    if sched.get_job(_job_id(schedule_id)) is not None:
        sched.remove_job(_job_id(schedule_id))
    with session_scope() as session:
        obj = session.get(Schedule, schedule_id)
        if obj is None:
            return False
        session.delete(obj)
        return True


def list_schedules() -> list[dict]:
    with session_scope() as session:
        return [as_dict(s) for s in session.scalars(select(Schedule).order_by(Schedule.id)).all()]


def get_schedule(schedule_id: int) -> dict | None:
    with session_scope() as session:
        sched = session.get(Schedule, schedule_id)
        return as_dict(sched) if sched is not None else None

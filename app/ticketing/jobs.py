"""Jira delivery worker. Runs on the Monitoring module's APScheduler (no second scheduler):
periodically (CAG_JIRA_DELIVERY_INTERVAL_MINUTES) and right after each correlation run.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

from .. import config, database
from . import service

log = logging.getLogger(__name__)

JOB_ID = "cag-jira"


def deliver() -> None:
    """Queue qualifying findings, then send due tickets and notes. Never raises."""
    if service.state()[0] != "enabled":
        return
    try:
        jira = service.client()
        with next(database.get_session()) as session:
            service.enqueue_qualifying(session)           # catches risk changes outside correlation runs
            outcome = service.deliver_due(session, jira)
        if outcome:
            log.info("Jira delivery: %s", ", ".join(f"{k} {v}" for k, v in sorted(outcome.items())))
    except Exception:  # noqa: BLE001 - the worker must keep running; rows stay queued
        log.exception("Jira delivery run failed")


def dispatch() -> None:
    """Deliver soon, in the background (after a correlation run)."""
    if service.state()[0] != "enabled":
        return
    from ..correlation.jobs import run_in_background
    run_in_background(deliver)


def register(scheduler) -> None:
    current, problem = service.state()
    if current == "disabled":
        log.info("Jira ticket creation disabled")
        return
    if current == "misconfigured":
        log.error("Jira ticket creation is enabled but misconfigured: %s - no tickets will be created", problem)
        return
    scheduler.add_job(deliver, trigger="interval", minutes=config.JIRA_DELIVERY_INTERVAL_MINUTES, id=JOB_ID,
                      replace_existing=True, max_instances=1, coalesce=True,
                      next_run_time=datetime.now() + timedelta(minutes=1))
    log.info("Jira ticket creation enabled for project %s (%s), every %d min", config.JIRA_PROJECT_KEY,
             config.JIRA_BASE_URL, config.JIRA_DELIVERY_INTERVAL_MINUTES)

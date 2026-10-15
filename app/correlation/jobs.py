"""Automatic correlation: after each version scan, and a periodic refresh job.

Jobs run on the Monitoring module's APScheduler instance, so they never block
a scan or an API request.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta

from .. import config, database
from ..database import utcnow
from . import engine, kev
from .models import FeedSync
from .nvd import NvdClient

log = logging.getLogger(__name__)

JOB_ID = "cag-correlation"


def nvd_client() -> NvdClient:
    return NvdClient(api_key=config.NVD_API_KEY)


def correlate_after_scan(scan_id: int) -> None:
    """Re-correlate the assets seen in a finished version scan. Never raises."""
    try:
        with next(database.get_session()) as session:
            from .sources import assets_for_scan
            asset_ids = assets_for_scan(session, scan_id)
            if asset_ids:
                engine.run_correlation(session, nvd_client(), asset_ids, trigger="scan")
    except Exception:  # noqa: BLE001
        log.exception("correlation after scan %s failed", scan_id)


def execute_queued_run(run_id: int, asset_ids: list[str] | None) -> None:
    """Background part of POST /correlation/run. Never raises."""
    try:
        with next(database.get_session()) as session:
            engine.run_correlation(session, nvd_client(), asset_ids, trigger="manual", run_id=run_id)
    except Exception:  # noqa: BLE001
        log.exception("queued correlation run %s failed", run_id)


def run_in_background(func, *args) -> None:
    """Run on the Monitoring scheduler's thread pool, or a plain thread when it is not running."""
    from ..monitoring.scheduler import get_scheduler
    scheduler = get_scheduler()
    if scheduler.running:
        scheduler.add_job(func, args=list(args))
    else:
        threading.Thread(target=func, args=args, daemon=True, name="correlation-run").start()


def on_startup() -> None:
    """Mark runs interrupted by a crash or restart as failed (they would block new runs)."""
    with next(database.get_session()) as session:
        swept = engine.sweep_interrupted_runs(session)
    if swept:
        log.warning("%d interrupted correlation run(s) marked as failed", swept)


def schedule_after_scan(scan_id: int) -> None:
    """Called by Monitoring when a version scan completed: correlate in the background."""
    if not config.CORRELATION_AFTER_SCAN:
        return
    from ..monitoring.scheduler import get_scheduler
    scheduler = get_scheduler()
    if scheduler.running:
        scheduler.add_job(correlate_after_scan, args=[scan_id], id=f"correlation-scan-{scan_id}",
                          replace_existing=True)


def periodic_refresh() -> None:
    """Refresh KEV and changed CVEs, then re-correlate every active asset. Never raises."""
    try:
        with next(database.get_session()) as session:
            nvd = nvd_client()
            try:
                kev.refresh(session, max_age=timedelta(hours=20))
            except Exception:  # noqa: BLE001 - keep the cached catalogue
                session.rollback()
                log.warning("KEV refresh failed - using the cached catalogue", exc_info=True)
            last = session.get(FeedSync, engine.NVD_MODIFIED_FEED)
            try:
                engine.sync_modified_cves(session, nvd, since=last.last_synced if last else utcnow() - timedelta(days=1))
            except Exception:  # noqa: BLE001
                session.rollback()
                log.warning("NVD incremental update failed - using cached CVE data", exc_info=True)
            engine.run_correlation(session, nvd, trigger="scheduled")
    except Exception:  # noqa: BLE001
        log.exception("periodic correlation failed")


def register(scheduler) -> None:
    if config.CORRELATION_INTERVAL_HOURS <= 0:
        return
    scheduler.add_job(periodic_refresh, trigger="interval", hours=config.CORRELATION_INTERVAL_HOURS,
                      id=JOB_ID, replace_existing=True, next_run_time=datetime.now() + timedelta(minutes=10))
    log.info("vulnerability correlation every %dh (NVD API key: %s)", config.CORRELATION_INTERVAL_HOURS,
             "configured" if config.NVD_API_KEY else "not set")

"""Correlation engine: store NVD CVEs and maintain findings per asset (S5.2, S5.4).

Lifecycle of a finding (never deleted):
  new match                          -> open
  still matching                     -> status kept, last_seen updated
  no longer matching after new data  -> resolved (verified_fixed if a ticket exists)
  matching again after being closed  -> open (reopened)
Findings of a source without fresh data (no new scan, NVD down without cache) are left alone.
"""
from __future__ import annotations

import logging
import re
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..assets.models import Asset, LifecycleStatus
from ..audit import service as audit
from ..database import utcnow
from ..risk import service as risk
from ..ticketing import jobs as ticketing_jobs
from ..ticketing import service as ticketing
from . import sources
from .cpe import CpeParts, identify, parse_cpe
from .cvss import extract_cvss
from .models import (
    CLOSED_STATUSES,
    CorrelationRun,
    Cve,
    CveCpeMatch,
    FeedSync,
    Finding,
    FindingStatus,
    KevEntry,
    ProductSync,
    SoftwareSource,
)
from .nvd import NvdClient, NvdError
from .versions import compare_versions, in_range

log = logging.getLogger(__name__)

_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
NVD_MODIFIED_FEED = "nvd_modified"
ACTIVE_RUN_STATUSES = ("queued", "running")
NO_SOFTWARE_PREFIX = "no software data"


def no_software_data(asset: Asset, scan_available: bool) -> str:
    """Why nothing could be checked - kept on the asset's risk summary, not in the run log."""
    if scan_available:
        why = "the latest version scan identified no software"
    elif asset.ip_address:
        why = f"no completed version scan of {asset.ip_address}"
    else:
        why = "no IP address to match scans"
    return f"{NO_SOFTWARE_PREFIX}: {why} and no manual software - nothing could be checked"

# One correlation run at a time in this process: the periodic job, scan-triggered runs and
# manual runs would otherwise update the same findings concurrently. Across processes
# (PostgreSQL), correlate_asset additionally locks the asset row (SELECT ... FOR UPDATE).
_RUN_LOCK = threading.Lock()


class CorrelationBusy(RuntimeError):
    pass


def cache_max_age() -> timedelta:
    return timedelta(hours=config.NVD_CACHE_HOURS)


# --- Storing NVD data -------------------------------------------------------------------------

def _parse_dt(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _vulnerable_matches(data: dict) -> Iterator[tuple[dict, CpeParts, bool]]:
    """(cpeMatch, parsed CPE, platform_dependent) for every vulnerable criterion.

    In an AND configuration ("app X running on platform Y") only the vulnerable part
    is used; the platform condition cannot be checked and is flagged instead.
    """
    for config_ in data.get("configurations") or []:
        if not isinstance(config_, dict):
            continue
        nodes = [n for n in config_.get("nodes") or [] if isinstance(n, dict)]
        platform_dependent = config_.get("operator") == "AND" and len(nodes) > 1
        for node in nodes:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict) or not match.get("vulnerable"):
                    continue
                parts = parse_cpe(str(match.get("criteria", "")))
                if parts and parts.part == "a":
                    yield match, parts, platform_dependent


def store_cve(session: Session, data: dict) -> Cve | None:
    """Insert or update one CVE from an NVD API 2.0 'cve' object. Malformed records are skipped."""
    cve_id = data.get("id")
    if not isinstance(cve_id, str) or not _CVE_ID.fullmatch(cve_id):
        return None
    cve = session.get(Cve, cve_id)
    if cve is None:
        cve = Cve(id=cve_id)
        session.add(cve)
    cve.description = next((str(d.get("value", "")) for d in data.get("descriptions") or []
                            if isinstance(d, dict) and d.get("lang") == "en"), "")
    cve.published = _parse_dt(data.get("published"))
    cve.last_modified = _parse_dt(data.get("lastModified"))
    cvss = extract_cvss(data)
    cve.cvss_version, cve.cvss_score, cve.cvss_vector, cve.severity = (
        cvss.version, cvss.score, cvss.vector, cvss.severity)
    kev = session.get(KevEntry, cve_id)
    cve.known_exploited = kev is not None
    cve.kev_date_added = kev.date_added if kev else None
    cve.fetched_at = utcnow()

    rows: dict[tuple, CveCpeMatch] = {}
    for match, parts, platform_dependent in _vulnerable_matches(data):
        bounds = tuple(str(match[k])[:100] if match.get(k) else None for k in (
            "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"))
        key = (match["criteria"], *bounds)
        if key in rows:
            continue
        rows[key] = CveCpeMatch(
            criteria=str(match["criteria"])[:300], vendor=parts.vendor[:100], product=parts.product[:100],
            version=parts.version, cpe_update=parts.update,
            version_start_including=bounds[0], version_start_excluding=bounds[1],
            version_end_including=bounds[2], version_end_excluding=bounds[3],
            platform_dependent=platform_dependent)
    cve.matches = list(rows.values())
    session.flush()  # so a CVE repeated in the same batch is found by session.get
    return cve


def ensure_product_cves(session: Session, nvd: NvdClient, vendor: str, product: str,
                        max_age: timedelta) -> str:
    """Make the CVEs of vendor:product available locally.

    Returns 'cached', 'fetched' or 'stale' (NVD failed, older cache used).
    Raises NvdError only when NVD fails and nothing is cached.
    """
    sync = session.get(ProductSync, (vendor, product))
    if sync and utcnow() - sync.last_synced < max_age:
        return "cached"
    try:
        count = sum(1 for data in nvd.cves_for_product(vendor, product) if store_cve(session, data))
    except NvdError as exc:
        if sync is None:
            raise
        log.warning("NVD unavailable for %s:%s (%s) - using cache from %s", vendor, product, exc,
                    sync.last_synced.isoformat())
        return "stale"
    if sync is None:
        sync = ProductSync(vendor=vendor, product=product)
        session.add(sync)
    sync.last_synced = utcnow()
    sync.cve_count = count
    session.flush()
    return "fetched"


def sync_modified_cves(session: Session, nvd: NvdClient, since: datetime, until: datetime | None = None) -> int:
    """Refresh CVEs changed since `since` that affect tracked products or are already stored."""
    until = until or utcnow()
    tracked = {tuple(row) for row in session.execute(select(ProductSync.vendor, ProductSync.product))}
    updated = 0
    start = since
    while start < until:
        end = min(start + timedelta(days=120), until)
        for data in nvd.cves_modified_between(start.astimezone(UTC), end.astimezone(UTC)):
            relevant = any((p.vendor, p.product) in tracked for _, p, _ in _vulnerable_matches(data))
            if relevant or session.get(Cve, data.get("id")) is not None:
                if store_cve(session, data):
                    updated += 1
        start = end
    sync = session.get(FeedSync, NVD_MODIFIED_FEED) or FeedSync(name=NVD_MODIFIED_FEED)
    sync.last_synced, sync.item_count = until, updated
    session.add(sync)
    session.commit()
    return updated


# --- Matching ---------------------------------------------------------------------------------

def matches_version(row: CveCpeMatch, version: str | None) -> bool:
    """Does a (normalised) software version fall under this CPE criterion?"""
    if row.version == "-":  # "not applicable"
        return False
    bounds = (row.version_start_including, row.version_start_excluding,
              row.version_end_including, row.version_end_excluding)
    has_range = any(bounds)
    if version is None:
        # Unknown version: only criteria that cover every version can match.
        return row.version is None and not has_range
    if row.version is not None:
        return _exact_version_match(row, version)
    if has_range:
        return in_range(version, *bounds)
    return True  # "*" without range = all versions


def _exact_version_match(row: CveCpeMatch, version: str) -> bool:
    update = row.cpe_update if row.cpe_update not in (None, "-") else ""
    if compare_versions(version, row.version + update) == 0:
        return True
    if row.cpe_update is None:
        # "7.4" with any update also covers "7.4p1" - but not "7.41" or "7.4.1".
        rest = version[len(row.version):] if version.startswith(row.version) else ""
        return bool(rest) and rest[0].isalpha()
    return False


# --- Findings ---------------------------------------------------------------------------------

@dataclass
class AssetResult:
    opened: int = 0
    reopened: int = 0
    closed: int = 0
    unmapped: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    no_data: str | None = None          # nothing could be checked (shown on the asset, not the run)


def correlate_asset(session: Session, asset: Asset, nvd: NvdClient, max_age: timedelta) -> AssetResult:
    """Create, update, close and reopen the findings of one asset (idempotent)."""
    # Serialise work on this asset across processes until the caller commits
    # (FOR UPDATE is a no-op on SQLite, which allows only one writer anyway).
    session.execute(select(Asset.id).where(Asset.id == asset.id).with_for_update())
    now = utcnow()
    result = AssetResult()
    view = sources.collect(session, asset)
    result.warnings.extend(view.warnings)
    if not view.items and not view.warnings:
        # Nothing to check is not the same as nothing found - say so (the risk summary shows it).
        result.no_data = no_software_data(asset, view.scan_available)

    matched: dict[tuple[str, str], tuple] = {}
    # (port, product) seen again with a known version AND fresh CVE data: the only proof that
    # lets a finding of that product on that port be closed.
    proof_of_state: set[tuple[int | None, str]] = set()
    for item in view.items:
        identities = identify(item.product, item.version, item.cpe)
        if not identities:
            result.unmapped.add(item.product[:100])
            continue
        if all(ident.version is None for ident in identities):
            # No version, no finding: never matched, never used to close anything.
            result.warnings.append(f"{item.product[:100]} (port {item.port or '-'}): version unknown, not matched")
            continue
        for ident in identities:
            if ident.version is None:
                continue
            try:
                state = ensure_product_cves(session, nvd, ident.vendor, ident.product, max_age)
            except NvdError as exc:
                result.warnings.append(f"{ident.key}: {exc}")
                continue
            if state == "stale":
                result.warnings.append(f"{ident.key}: NVD unreachable, using cached CVE data "
                                       "(findings are not closed)")
            else:
                proof_of_state.add((item.port, ident.key))
            rows = session.scalars(select(CveCpeMatch).where(
                CveCpeMatch.vendor == ident.vendor, CveCpeMatch.product == ident.product))
            for row in rows:
                if matches_version(row, ident.version):
                    matched.setdefault((row.cve_id, ident.key), (item, ident, row.platform_dependent))

    findings = session.scalars(select(Finding).where(Finding.asset_id == asset.id)).unique().all()
    by_key = {(f.cve_id, f.product_key): f for f in findings}

    for (cve_id, product_key), (item, ident, platform_dependent) in matched.items():
        confidence = "low" if ident.confidence == "low" or platform_dependent else "high"
        finding = by_key.get((cve_id, product_key))
        if finding is None:
            finding = Finding(asset_id=asset.id, cve_id=cve_id, product_key=product_key,
                              first_seen=now, status=FindingStatus.OPEN, status_changed_at=now)
            session.add(finding)
            result.opened += 1
        elif finding.status in CLOSED_STATUSES:
            _audit_transition(session, finding, asset, FindingStatus.OPEN, "finding.auto_reopen")
            ticketing.add_note(session, finding, f"{cve_id} reopened on {asset.name}: the vulnerable version "
                               f"was detected again ({item.product} {item.version or 'version unknown'}).")
            finding.status = FindingStatus.OPEN
            finding.status_reason = "vulnerable version detected again"
            finding.status_changed_at = now
            finding.resolved_at = None
            result.reopened += 1
        finding.software = item.product[:200]
        finding.version = (item.version or None) and item.version[:100]
        finding.port, finding.protocol, finding.source = item.port, item.protocol, item.source
        finding.matched_cpe = ident.cpe
        finding.confidence = confidence
        finding.last_seen = now
        if item.source == SoftwareSource.SCAN:
            finding.last_scan_id = view.scan_id

    fresh_sources = {SoftwareSource.MANUAL} | ({SoftwareSource.SCAN} if view.scan_available else set())
    for finding in findings:
        if (finding.cve_id, finding.product_key) in matched or finding.status in CLOSED_STATUSES:
            continue
        if finding.source not in fresh_sources:
            continue
        # Close only on proof: the same product on the same port now runs a known, non-affected
        # version, checked against fresh CVE data. A port that went quiet, another product on the
        # port, an unknown version or stale/failed NVD data keep the finding open.
        if (finding.port, finding.product_key) not in proof_of_state:
            continue
        if finding.source == SoftwareSource.SCAN and finding.last_scan_id == view.scan_id:
            continue  # same scan as before: nothing new to conclude
        new_status = FindingStatus.VERIFIED_FIXED if finding.ticket_key else FindingStatus.RESOLVED
        _audit_transition(session, finding, asset, new_status, "finding.auto_close")
        ticketing.add_note(session, finding, f"Verification: {finding.cve_id} on {asset.name} is "
                           f"{new_status.value.replace('_', ' ')} - {finding.software} on port "
                           f"{finding.port or '-'} now runs a version that is not affected (checked against "
                           "current CVE data). Please verify and close this issue per your workflow.")
        finding.status = new_status
        finding.status_reason = "same product on the same port now runs a non-affected version"
        finding.status_changed_at = finding.resolved_at = now
        result.closed += 1

    session.flush()
    return result


def _audit_transition(session: Session, finding: Finding, asset: Asset, new_status: FindingStatus,
                      action: str) -> None:
    """Automatic status changes are audit-logged like analyst changes (same transaction)."""
    audit.record(session, audit.SYSTEM, action, target_type="finding", target_id=str(finding.id),
                 target_label=f"{finding.cve_id} on {asset.name}",
                 details={"status": {"from": finding.status.value, "to": new_status.value}})


def queue_run(session: Session, trigger: str) -> CorrelationRun:
    """Create a 'queued' run record, or raise CorrelationBusy if one is queued or running."""
    active = session.scalar(select(CorrelationRun).where(CorrelationRun.status.in_(ACTIVE_RUN_STATUSES))
                            .order_by(CorrelationRun.id).limit(1))
    if active is not None or _RUN_LOCK.locked():
        raise CorrelationBusy(f"Correlation run {active.id} is still in progress" if active
                              else "A correlation run is still in progress")
    run = CorrelationRun(trigger=trigger, status="queued", started_at=utcnow())
    session.add(run)
    session.commit()
    return run


def sweep_interrupted_runs(session: Session) -> int:
    """At startup: runs left 'queued'/'running' by a crash or restart are marked failed."""
    runs = session.scalars(select(CorrelationRun).where(CorrelationRun.status.in_(ACTIVE_RUN_STATUSES))).all()
    for run in runs:
        run.status = "failed"
        run.finished_at = run.finished_at or utcnow()
        run.warnings = (run.warnings + "\n" if run.warnings else "") + "interrupted (application restarted)"
    session.commit()
    return len(runs)


def run_correlation(session: Session, nvd: NvdClient, asset_ids: list[str] | None = None,
                    trigger: str = "manual", max_age: timedelta | None = None,
                    run_id: int | None = None) -> CorrelationRun:
    """Correlate active assets (all, or the given ids) and log the run. Never raises.

    Waits while another run in this process is active. `run_id` continues a run
    created by queue_run().
    """
    with _RUN_LOCK:
        return _run(session, nvd, asset_ids, trigger, max_age, run_id)


def _run(session: Session, nvd: NvdClient, asset_ids: list[str] | None, trigger: str,
         max_age: timedelta | None, run_id: int | None) -> CorrelationRun:
    max_age = cache_max_age() if max_age is None else max_age
    run = session.get(CorrelationRun, run_id) if run_id is not None else None
    if run is None:
        run = CorrelationRun(trigger=trigger, started_at=utcnow())
        session.add(run)
    run.status = "running"
    run.started_at = utcnow()
    run.scope = "all" if asset_ids is None else "selected"
    session.commit()
    warnings: list[str] = []
    unmapped: set[str] = set()
    try:
        query = select(Asset).where(Asset.status == LifecycleStatus.ACTIVE).order_by(Asset.name)
        if asset_ids is not None:
            query = query.where(Asset.id.in_(asset_ids))
        for asset in session.scalars(query).all():
            result = correlate_asset(session, asset, nvd, max_age)
            try:                           # a scoring error must not cost the asset its findings
                with session.begin_nested():
                    risk.score_asset(session, asset, warnings=[
                        *result.warnings, *([result.no_data] if result.no_data else []),
                        *(f"{name}: product not in the CPE catalogue, not matched" for name in sorted(result.unmapped)),
                    ], trigger="correlation", run_id=run.id)
            except Exception as exc:  # noqa: BLE001
                log.exception("risk scoring failed for asset %s", asset.id)
                result.warnings.append(f"risk scoring failed ({type(exc).__name__}) - previous risk kept")
            run.assets_processed += 1
            run.findings_opened += result.opened
            run.findings_reopened += result.reopened
            run.findings_closed += result.closed
            unmapped |= result.unmapped
            warnings.extend(f"{asset.name}: {w}" for w in result.warnings)
            session.commit()
        run.status = "partial" if warnings else "success"
    except Exception as exc:  # noqa: BLE001 - a failed run must not break scans or the scheduler
        session.rollback()
        log.exception("correlation run %s failed", run.id)
        run.status = "failed"
        warnings.append(f"{type(exc).__name__}: {exc}")
    run.finished_at = utcnow()
    run.duration_seconds = (run.finished_at - run.started_at).total_seconds()
    run.unmapped_software = ", ".join(sorted(unmapped))[:2000]
    run.warnings = "\n".join(warnings)[:10000]
    session.commit()
    from ..dashboard import service as dashboard  # lazy: the dashboard reads correlation data
    dashboard.record_snapshot_safely(session, commit=True)   # organisation posture after the run
    log.info("correlation run %s (%s): %s - %d assets, %d opened, %d reopened, %d closed, %.1fs",
             run.id, trigger, run.status, run.assets_processed, run.findings_opened,
             run.findings_reopened, run.findings_closed, run.duration_seconds)
    if run.status in ("success", "partial"):
        _queue_jira_tickets(session, run, asset_ids)
    return run


def _queue_jira_tickets(session: Session, run: CorrelationRun, asset_ids: list[str] | None) -> None:
    """Queue Jira tasks for qualifying findings (database only; Jira is called by the worker).

    Runs after the run's result is committed, so a failure here can never roll the run back
    to 'running' or change its status. It is logged and noted on the run; the Jira worker's
    periodic sweep queues the findings later.
    """
    try:
        if ticketing.enqueue_qualifying(session, asset_ids):
            ticketing_jobs.dispatch()
    except Exception as exc:  # noqa: BLE001 - ticketing must never change a run's result
        session.rollback()
        log.exception("queueing Jira tasks after correlation run %s failed", run.id)
        note = f"Jira tasks not queued ({type(exc).__name__}); the Jira worker retries"
        try:
            run.warnings = (f"{run.warnings}\n{note}" if run.warnings else note)[:10000]
            session.commit()
        except Exception:  # noqa: BLE001 - the database itself may be failing; already logged above
            session.rollback()
            log.exception("could not record the Jira queueing failure on correlation run %s", run.id)

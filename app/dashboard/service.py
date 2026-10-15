"""Executive dashboard figures, computed from persisted data only.

Nothing here scores a vulnerability: finding risk comes from the stored Risk Engine results
(finding_risk), asset coverage from asset_risk, lifecycle history from findings.first_seen and
the append-only audit log, trends from the daily security_snapshots.

Definitions (all times UTC; a month is [first day 00:00, first day of next month 00:00)):
  unresolved finding     status open or in_remediation (accepted_risk, resolved and
                         verified_fixed are not unresolved) on an active asset
  open critical          unresolved findings whose stored risk level is CRITICAL
  assets at risk         active assets with at least one unresolved finding of risk >= 65
                         (the Risk Engine's HIGH threshold)
  assessed asset         active asset with an assessment result that is not "no software
                         data" (assets without any data cannot be scored and are not "clean")
  new in month           findings whose first_seen lies in the month. A finding is unique per
                         (asset, CVE, product) and keeps first_seen when it reopens, so repeated
                         observations are never counted again. Includes findings of assets that
                         were deactivated later (history), unlike the "open" counts (active assets).
  resolved in month      distinct findings with a "finding.auto_close" audit event in the month
                         (closed by a re-scan showing a non-affected version). Taken from the
                         append-only audit log because findings.resolved_at is cleared on reopen.
  remediation rate       resolved / (unresolved at month start + new + reopened in the month);
                         "unresolved at month start" comes from the latest posture snapshot before
                         the month (every finding or risk change writes one, so it is the state at
                         the boundary) - unavailable before the first snapshot.

Security Score (method version 1), 0-100, higher is better:
  W = highest risk score among unresolved findings of assessed active assets (0 if none)
  B = share of assessed active assets that are at risk, in percent
  (W and B use the same asset set as the denominator; open findings on assets without software
  data are reported as open_outside_score, so the score always stays within 0-100)
  score = 100 - round_half_up(0.5 * W + 0.5 * B); unavailable when no asset is assessed.
  W keeps a single severe risk from being averaged away; B reflects how widespread serious
  risk is. Accepted risks and assets without data are excluded (coverage is reported next to it).
"""
from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from fractions import Fraction

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..assets.models import Asset, LifecycleStatus
from ..audit.models import AuditEvent
from ..correlation.models import CorrelationRun, Cve, FeedSync, Finding, FindingStatus, ProductSync
from ..database import utcnow
from ..monitoring.models import Scan
from ..risk import engine as risk_engine
from ..risk.models import AssetRisk, FindingRisk
from .models import SecuritySnapshot

log = logging.getLogger(__name__)

METHOD_VERSION = "1"
AT_RISK_THRESHOLD = next(t for t, level in risk_engine.LEVELS if level == "HIGH")     # 65
UNRESOLVED = (FindingStatus.OPEN, FindingStatus.IN_REMEDIATION)
LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
NO_SOFTWARE_PREFIX = "no software data"            # app.correlation.engine.NO_SOFTWARE_PREFIX
ACTIVE_RUN_STATUSES = ("queued", "running")        # app.correlation.engine.ACTIVE_RUN_STATUSES
TREND_DAYS = 400
SERIES_MONTHS = 12
_MONTH = re.compile(r"(\d{4})-(0[1-9]|1[0-2])")


class InvalidPeriod(ValueError):
    pass


# --- periods --------------------------------------------------------------------------------------

def month_bounds(year: int, month: int) -> tuple[datetime, datetime]:
    start = datetime(year, month, 1, tzinfo=UTC)
    end = datetime(year + (month == 12), month % 12 + 1, 1, tzinfo=UTC)
    return start, end


def previous_month(year: int, month: int) -> tuple[int, int]:
    return (year - 1, 12) if month == 1 else (year, month - 1)


def parse_month(value: str | None, now: datetime) -> tuple[int, int]:
    """'YYYY-MM' (default: current UTC month). Future months and years before 2000 are invalid."""
    if not value:
        return now.year, now.month
    m = _MONTH.fullmatch(value)
    if not m:
        raise InvalidPeriod("month must look like YYYY-MM")
    year, month = int(m.group(1)), int(m.group(2))
    if year < 2000 or (year, month) > (now.year, now.month):
        raise InvalidPeriod("month must lie between 2000-01 and the current month")
    return year, month


# --- current posture ----------------------------------------------------------------------------------

def _round_half_up(value: Fraction) -> int:
    return int((Decimal(value.numerator) / Decimal(value.denominator)).to_integral_value(ROUND_HALF_UP))


def security_score(worst: int, at_risk: int, assessed: int) -> int | None:
    """The documented formula (method version 1). Deterministic: integers in, integer out."""
    if assessed <= 0:
        return None
    breadth = Fraction(at_risk * 100, assessed)
    return 100 - _round_half_up(Fraction(worst, 2) + breadth / 2)


def _no_data(warnings_json: str) -> bool:
    try:
        warnings = json.loads(warnings_json or "[]")
    except ValueError:
        return False
    return any(str(w).startswith(NO_SOFTWARE_PREFIX) for w in warnings)


def posture(session: Session) -> dict:
    """Organisation-level posture now. Three aggregate queries, no per-asset loop over findings."""
    active = Asset.status == LifecycleStatus.ACTIVE
    assets_active = session.scalar(select(func.count()).select_from(Asset).where(active)) or 0
    risk_rows = session.execute(select(AssetRisk.asset_id, AssetRisk.correlation_warnings)
                                .join(Asset, Asset.id == AssetRisk.asset_id).where(active)).all()
    no_data = {asset_id for asset_id, warnings in risk_rows if _no_data(warnings)}
    scoreable = {asset_id for asset_id, _ in risk_rows} - no_data
    assessed = len(scoreable)

    unresolved = (select(Finding.asset_id, FindingRisk.score, FindingRisk.level)
                  .join(Asset, Asset.id == Finding.asset_id)
                  .outerjoin(FindingRisk, FindingRisk.finding_id == Finding.id)
                  .where(active, Finding.status.in_(UNRESOLVED)))
    by_level = dict.fromkeys(LEVELS, 0)
    unscored = 0
    outside_score = 0                       # open findings on assets that are not (or no longer) assessable
    worst = 0
    at_risk_assets: set[str] = set()
    for asset_id, score, level in session.execute(unresolved):
        if score is None:
            unscored += 1                   # not assessed yet - shown, never counted as low risk
            continue
        by_level[level] = by_level.get(level, 0) + 1
        if asset_id not in scoreable:       # score inputs must match the denominator (assessed assets)
            outside_score += 1
            continue
        worst = max(worst, score)
        if score >= AT_RISK_THRESHOLD:
            at_risk_assets.add(asset_id)
    return {
        "security_score": security_score(worst, len(at_risk_assets), assessed),
        "method_version": METHOD_VERSION,
        "worst_asset_risk": worst if assessed else None,
        "assets_active": assets_active,
        "assets_assessed": assessed,
        "assets_no_data": len(no_data),
        "assets_never_assessed": max(assets_active - len(risk_rows), 0),
        "assets_at_risk": len(at_risk_assets),
        "open_findings": sum(by_level.values()) + unscored,
        "open_by_level": by_level,
        "open_unscored": unscored,
        "open_outside_score": outside_score,
    }


def record_snapshot(session: Session, now: datetime | None = None) -> SecuritySnapshot:
    """Upsert today's (UTC) snapshot with the current posture. The caller commits."""
    now = now or utcnow()
    p = posture(session)
    row = session.get(SecuritySnapshot, now.date()) or SecuritySnapshot(day=now.date())
    row.taken_at, row.security_score, row.method_version = now, p["security_score"], p["method_version"]
    row.worst_asset_risk, row.assets_active = p["worst_asset_risk"], p["assets_active"]
    row.assets_assessed, row.assets_at_risk = p["assets_assessed"], p["assets_at_risk"]
    row.open_findings, row.open_unscored = p["open_findings"], p["open_unscored"]
    row.open_critical, row.open_high = p["open_by_level"]["CRITICAL"], p["open_by_level"]["HIGH"]
    row.open_medium, row.open_low = p["open_by_level"]["MEDIUM"], p["open_by_level"]["LOW"]
    session.add(row)
    session.flush()
    return row


def record_snapshot_safely(session: Session, *, commit: bool = False) -> None:
    """Hook for state changes: a snapshot problem must never break an assessment or an edit."""
    try:
        with session.begin_nested():
            record_snapshot(session)
        if commit:
            session.commit()
    except Exception:  # noqa: BLE001
        if commit:
            session.rollback()             # keep the session usable for the caller
        log.exception("could not record the security posture snapshot")


# --- monthly figures (lifecycle history) ----------------------------------------------------------------

def _resolved_ids(session: Session, start: datetime, end: datetime, action: str = "finding.auto_close") -> set:
    return set(session.scalars(select(AuditEvent.target_id).where(
        AuditEvent.action == action, AuditEvent.occurred_at >= start, AuditEvent.occurred_at < end)))


def _snapshot_before(session: Session, day: date) -> SecuritySnapshot | None:
    """Latest snapshot before `day`. Every event that changes findings or their risk writes a
    snapshot, so the latest one before a boundary is the state at that boundary."""
    return session.scalars(select(SecuritySnapshot).where(SecuritySnapshot.day < day)
                           .order_by(SecuritySnapshot.day.desc()).limit(1)).first()


def month_figures(session: Session, year: int, month: int) -> dict:
    start, end = month_bounds(year, month)
    new_rows = session.execute(
        select(Finding.id, FindingRisk.level).outerjoin(FindingRisk, FindingRisk.finding_id == Finding.id)
        .where(Finding.first_seen >= start, Finding.first_seen < end)).all()
    new_by_level = dict.fromkeys(LEVELS, 0)
    for _, level in new_rows:
        if level in new_by_level:
            new_by_level[level] += 1
    resolved = _resolved_ids(session, start, end)
    reopened = _resolved_ids(session, start, end, "finding.auto_reopen")
    accepted = _resolved_ids(session, start, end, "finding.accept_risk")

    start_snapshot = _snapshot_before(session, start.date())
    rate: float | None
    rate_reason: str | None
    workload: int | None
    if start_snapshot is None:
        rate, rate_reason, workload = None, ("needs a posture snapshot from before the month "
                                             "(snapshots are recorded from this version on)"), None
    else:
        workload = start_snapshot.open_findings + len(new_rows) + len(reopened)
        rate = None if workload == 0 else round(100 * len(resolved) / workload, 1)
        rate_reason = "no unresolved or new findings in the month" if workload == 0 else None
    return {
        "month": f"{year:04d}-{month:02d}",
        "start": start, "end": end,
        "new_findings": len(new_rows),
        "new_by_level": new_by_level,           # risk level as currently scored
        "resolved_findings": len(resolved),
        "reopened_findings": len(reopened),
        "risk_accepted": len(accepted),
        "remediation_rate": rate,
        "remediation_rate_reason": rate_reason,
        "remediation_workload": workload,
        "unresolved_at_start": start_snapshot.open_findings if start_snapshot else None,
        "start_snapshot_day": start_snapshot.day if start_snapshot else None,
    }


def monthly_series(session: Session, year: int, month: int, months: int = SERIES_MONTHS) -> list[dict]:
    """New vs resolved per month for the `months` months ending with year-month (two queries)."""
    keys = []
    y, m = year, month
    for _ in range(months):
        keys.append((y, m))
        y, m = previous_month(y, m)
    keys.reverse()
    start, end = month_bounds(*keys[0])[0], month_bounds(*keys[-1])[1]
    new: dict[tuple[int, int], int] = defaultdict(int)
    for (first_seen,) in session.execute(select(Finding.first_seen).where(
            Finding.first_seen >= start, Finding.first_seen < end)):
        new[(first_seen.year, first_seen.month)] += 1
    resolved: dict[tuple, set] = defaultdict(set)
    for target_id, occurred_at in session.execute(select(AuditEvent.target_id, AuditEvent.occurred_at).where(
            AuditEvent.action == "finding.auto_close", AuditEvent.occurred_at >= start, AuditEvent.occurred_at < end)):
        resolved[(occurred_at.year, occurred_at.month)].add(target_id)
    return [{"month": f"{y:04d}-{m:02d}", "new": new[(y, m)], "resolved": len(resolved[(y, m)])}
            for y, m in keys]


# --- top risks, trends, health ------------------------------------------------------------------------

def top_risks(session: Session, limit: int = 5) -> list[dict]:
    """Same order as GET /findings?sort=risk: risk score, then KEV, then CVSS, then id."""
    rows = session.execute(
        select(Finding, FindingRisk).join(FindingRisk, FindingRisk.finding_id == Finding.id)
        .join(Asset, Asset.id == Finding.asset_id).join(Cve, Cve.id == Finding.cve_id)
        .where(Asset.status == LifecycleStatus.ACTIVE, Finding.status.in_(UNRESOLVED))
        .order_by(FindingRisk.score.desc(), Cve.known_exploited.desc(), Cve.cvss_score.desc().nulls_last(),
                  Finding.id).limit(limit)).unique().all()
    result = []
    for f, r in rows:
        result.append({
            "finding_id": f.id, "cve_id": f.cve_id, "nvd_url": f"https://nvd.nist.gov/vuln/detail/{f.cve_id}",
            "summary": (f.cve.description or "")[:220], "software": f.software, "version": f.version,
            "port": f.port, "protocol": f.protocol, "status": f.status.value,
            "known_exploited": f.cve.known_exploited, "cvss": f.cve.cvss_score,
            "risk_score": r.score, "risk_level": r.level, "why": r.why,
            "asset_id": f.asset_id, "asset_name": f.asset.name,
            "criticality": f.asset.criticality.value, "environment": f.asset.environment.value,
            "internet_facing": f.asset.internet_facing.value,
            "recommended_action": None,         # not recorded by the application yet
        })
    return result


def trend(session: Session, now: datetime) -> list[dict]:
    since = now.date() - timedelta(days=TREND_DAYS)
    rows = session.scalars(select(SecuritySnapshot).where(SecuritySnapshot.day >= since)
                           .order_by(SecuritySnapshot.day)).all()
    return [{"day": s.day, "security_score": s.security_score, "open_critical": s.open_critical,
             "open_high": s.open_high, "open_findings": s.open_findings, "assets_at_risk": s.assets_at_risk,
             "method_version": s.method_version} for s in rows]


def _run_dict(run: CorrelationRun | None) -> dict | None:
    if run is None:
        return None
    first = [w for w in (run.warnings or "").splitlines() if w][:3]
    return {"id": run.id, "trigger": run.trigger, "scope": run.scope or ("all" if run.trigger == "scheduled" else None),
            "status": run.status, "started_at": run.started_at, "finished_at": run.finished_at,
            "assets_processed": run.assets_processed, "warnings_count": len([w for w in (run.warnings or "").splitlines() if w]),
            "first_warnings": first}


def assessment_health(session: Session, now: datetime, schedule: dict) -> dict:
    finished = select(CorrelationRun).where(CorrelationRun.status.not_in(ACTIVE_RUN_STATUSES))
    last_run = session.scalars(finished.order_by(CorrelationRun.id.desc()).limit(1)).first()
    full = (CorrelationRun.scope == "all") | (CorrelationRun.scope.is_(None) & (CorrelationRun.trigger == "scheduled"))
    last_full = session.scalars(finished.where(full).order_by(CorrelationRun.id.desc()).limit(1)).first()
    problems = session.scalars(finished.where(CorrelationRun.status.in_(("partial", "failed")),
                                              CorrelationRun.started_at >= now - timedelta(days=30))
                               .order_by(CorrelationRun.id.desc()).limit(5)).all()
    nvd_oldest, nvd_newest = session.execute(select(func.min(ProductSync.last_synced),
                                                    func.max(ProductSync.last_synced))).one()
    last_scan = session.scalar(select(func.max(Scan.finished_at)).where(
        Scan.scan_type == "version", Scan.status == "completed"))
    kev = session.get(FeedSync, "cisa_kev")
    return {
        "last_run": _run_dict(last_run),
        "last_full_assessment": _run_dict(last_full),
        "recent_problem_runs": [_run_dict(r) for r in problems],
        "active_run": schedule.get("active_run"),
        "periodic_enabled": schedule.get("periodic_enabled"),
        "next_run_at": schedule.get("next_run_at"),
        "after_scan": schedule.get("after_scan"),
        "freshness": {
            "kev_last_synced": kev.last_synced if kev else None,
            "kev_current": schedule.get("kev_current"),
            "nvd_oldest_product_sync": nvd_oldest,
            "nvd_newest_product_sync": nvd_newest,
            "last_version_scan_at": last_scan,
        },
    }


# --- the dashboard ---------------------------------------------------------------------------------------

def summary(session: Session, year: int, month: int, schedule: dict, now: datetime | None = None) -> dict:
    now = now or utcnow()
    current = posture(session)
    is_current_month = (year, month) == (now.year, now.month)
    figures = month_figures(session, year, month)
    previous = month_figures(session, *previous_month(year, month))

    # Score comparison: the last snapshot before the selected month vs. now (current month) or
    # vs. the last snapshot of the selected month (past months). Never a recomputed value.
    start, end = month_bounds(year, month)
    baseline = _snapshot_before(session, start.date())
    score_now: int | None
    score_at: datetime | None
    if is_current_month:
        score_now, score_at = current["security_score"], now
    else:
        closing = _snapshot_before(session, end.date())
        closing = closing if closing and closing.day >= start.date() else None
        if closing is not None and closing.method_version != METHOD_VERSION:
            closing = None                  # a different method: not comparable, not shown
        score_now, score_at = (closing.security_score, closing.taken_at) if closing else (None, None)
    delta = (score_now - baseline.security_score
             if score_now is not None and baseline is not None and baseline.security_score is not None
             and baseline.method_version == METHOD_VERSION else None)

    return {
        "generated_at": now,
        "timezone": "UTC",
        "month": figures["month"],
        "is_current_month": is_current_month,
        "posture": current,
        "security_score": {
            "value": score_now, "at": score_at, "method_version": METHOD_VERSION,
            "baseline": baseline.security_score if baseline else None,
            "baseline_day": baseline.day if baseline else None,
            "change": delta,
            "unavailable_reason": None if score_now is not None else (
                "no asset with software data has been assessed yet" if is_current_month
                else "no posture snapshot recorded in this month"),
        },
        "month_figures": figures,
        "previous_month_figures": previous,
        "open_critical_now": current["open_by_level"]["CRITICAL"],
        "series": monthly_series(session, year, month),
        "trend": trend(session, now),
        "top_risks": top_risks(session),
        "health": assessment_health(session, now, schedule),
        "unavailable": {
            "overdue_actions": "remediation due dates are not recorded by the application",
            "recommended_action": "remediation guidance is not stored with findings yet",
        },
        "methodology": __doc__,
    }

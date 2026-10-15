"""Risk of findings and assets: the Risk Engine applied to the Correlation module's findings.

Inputs per finding (unknown stays unknown, see app.risk.engine):
  cvss            the CVE's CVSS base score; None when NVD has none
  internet_facing / criticality / environment   from the asset inventory
  kev             'yes' if the CVE is in CISA KEV; 'no' only when the KEV catalogue was
                  refreshed within KEV_MAX_AGE; otherwise 'unknown'
  public_exploit  'unknown' - the Correlation module does not record exploit references yet
  reachability    'open' when the evidence scan shows the port in state 'open';
                  'unknown' for 'open|filtered', manual software or a missing scan row
Scores are stored with the model version and recomputed (no network access) after every
correlation of the asset, a KEV refresh, an analyst status change and an asset context change.
"""
from __future__ import annotations

import json
import math
from datetime import datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..assets.models import Asset, LifecycleStatus
from ..correlation.models import FeedSync, Finding, FindingStatus, SoftwareSource
from ..database import utcnow
from . import engine
from .models import AssetRisk, AssetRiskHistory, FindingRisk

KEV_FEED_NAME = "cisa_kev"                 # app.correlation.kev.FEED_NAME
KEV_MAX_AGE = timedelta(hours=48)          # the periodic job refreshes it every ~20 h
OPEN_STATUSES = (FindingStatus.OPEN, FindingStatus.IN_REMEDIATION)
# Asset fields that feed the engine: a change triggers a rescore.
RISK_CONTEXT_FIELDS = frozenset({"criticality", "environment", "internet_facing"})


def kev_complete(session: Session, now: datetime | None = None) -> bool:
    sync = session.get(FeedSync, KEV_FEED_NAME)
    return sync is not None and (now or utcnow()) - sync.last_synced < KEV_MAX_AGE


class _PortStates:
    """Port states of the asset's evidence scans, one query per scan (not per finding)."""

    def __init__(self, session: Session, ip: str | None):
        self.session, self.ip = session, ip
        self.scans: dict[int, dict[tuple[int, str], str]] = {}

    def get(self, finding: Finding) -> str | None:
        if (finding.source != SoftwareSource.SCAN or finding.last_scan_id is None
                or finding.port is None or not self.ip):
            return None
        if finding.last_scan_id not in self.scans:
            rows = self.session.execute(text(
                "SELECT port, protocol, state FROM port_results WHERE scan_id = :scan AND ip = :ip"),
                {"scan": finding.last_scan_id, "ip": self.ip}).all()
            self.scans[finding.last_scan_id] = {(r[0], r[1]): r[2] for r in rows}
        states = self.scans[finding.last_scan_id]
        if finding.protocol:
            return states.get((finding.port, finding.protocol))
        return next((s for (port, _), s in states.items() if port == finding.port), None)


def inputs_for(finding: Finding, asset: Asset, kev_is_complete: bool, ports: _PortStates) -> dict:
    cve = finding.cve
    state = ports.get(finding)
    score = cve.cvss_score
    cvss = round(score, 1) if score is not None and math.isfinite(score) and 0 <= score <= 10 else None
    return {
        "cvss": cvss,                                    # an unusable score counts as unknown
        "internet_facing": asset.internet_facing.value,
        "criticality": asset.criticality.value,
        "environment": asset.environment.value,
        "kev": "yes" if cve.known_exploited else ("no" if kev_is_complete else "unknown"),
        "public_exploit": "unknown",
        "reachability": "open" if state == "open" else "unknown",
        "port": finding.port,
    }


def score_finding(session: Session, finding: Finding, asset: Asset, kev_is_complete: bool,
                  now: datetime, ports: _PortStates) -> FindingRisk:
    """Store the finding's risk. Unchanged results are not rewritten (assessed_at = last change)."""
    inputs = inputs_for(finding, asset, kev_is_complete, ports)
    result = engine.assess(**inputs)
    values = {"score": result.score, "level": result.level, "why": result.why,
              "factors": json.dumps(result.as_dict()["factors"]),
              "unknown_factors": json.dumps(list(result.unknown_factors)),
              "inputs": json.dumps(inputs), "model_version": result.model_version}
    row = session.get(FindingRisk, finding.id)
    if row is not None and all(getattr(row, k) == v for k, v in values.items()):
        return row
    row = row or FindingRisk(finding_id=finding.id)
    for key, value in values.items():
        setattr(row, key, value)
    row.assessed_at = now
    session.add(row)
    return row


def score_asset(session: Session, asset: Asset, *, warnings: list[str] | None = None,
                now: datetime | None = None, trigger: str = "rescore",
                run_id: int | None = None) -> AssetRisk:
    """Score every finding of the asset and refresh its summary. The caller commits.

    `warnings` (from a correlation run) replace the stored ones; None keeps them.
    A history entry is written when the asset's risk changed (or on its first assessment).
    """
    now = now or utcnow()
    kev_ok = kev_complete(session, now)
    session.flush()                        # make sure new findings have an id
    findings = session.scalars(select(Finding).where(Finding.asset_id == asset.id)).unique().all()
    ports = _PortStates(session, asset.ip_address)
    scored = [(f, score_finding(session, f, asset, kev_ok, now, ports)) for f in findings]

    active = [(f, r) for f, r in scored if f.status in OPEN_STATUSES]
    top = max((r for _, r in active), key=lambda r: r.score, default=None)
    summary = session.get(AssetRisk, asset.id) or AssetRisk(asset_id=asset.id, correlation_warnings="[]")
    summary.assessed_at = now
    summary.open_findings = len(active)
    summary.accepted_findings = sum(f.status == FindingStatus.ACCEPTED_RISK for f, _ in scored)
    summary.findings_with_unknowns = sum(json.loads(r.unknown_factors) != [] for _, r in active)
    summary.max_score = top.score if top else None
    summary.max_level = top.level if top else None
    if warnings is not None:
        summary.correlation_warnings = json.dumps(list(warnings))
    summary.model_version = engine.MODEL_VERSION
    session.add(summary)
    _record_history(session, summary, now, trigger, run_id)
    session.flush()
    return summary


def _record_history(session: Session, summary: AssetRisk, now: datetime, trigger: str,
                    run_id: int | None) -> None:
    last = session.scalars(select(AssetRiskHistory).where(AssetRiskHistory.asset_id == summary.asset_id)
                           .order_by(AssetRiskHistory.id.desc()).limit(1)).first()
    # Warnings are part of the state: "nothing could be checked" -> "checked, no findings" is a change.
    # (A KEV catalogue turning outdated after 48 h shows up under the next trigger that rescores.)
    state = (summary.max_score, summary.max_level, summary.open_findings, summary.accepted_findings,
             summary.model_version, summary.correlation_warnings)
    if last is not None and state == (last.max_score, last.max_level, last.open_findings,
                                      last.accepted_findings, last.model_version, last.correlation_warnings):
        return                              # unchanged: the correlation run log covers "assessed again"
    session.add(AssetRiskHistory(asset_id=summary.asset_id, recorded_at=now, trigger=trigger[:30],
                                 run_id=run_id, max_score=summary.max_score, max_level=summary.max_level,
                                 open_findings=summary.open_findings,
                                 accepted_findings=summary.accepted_findings,
                                 correlation_warnings=summary.correlation_warnings,
                                 model_version=summary.model_version))


def history(session: Session, asset_id: str, limit: int = 100) -> list[AssetRiskHistory]:
    return list(session.scalars(select(AssetRiskHistory).where(AssetRiskHistory.asset_id == asset_id)
                                .order_by(AssetRiskHistory.id.desc()).limit(limit)))


def rescore_asset(session: Session, asset: Asset, trigger: str = "rescore") -> None:
    """After an asset or finding change: only assets that were assessed before. Caller commits."""
    if session.get(AssetRisk, asset.id) is not None:
        score_asset(session, asset, trigger=trigger)


def rescore_all(session: Session) -> int:
    """After a KEV refresh: every assessed, active asset. Caller commits. Returns the asset count.

    Inactive assets keep their last assessment (correlation does not revisit them either);
    the API reports the asset status next to it.
    """
    assets = session.scalars(select(Asset).join(AssetRisk, AssetRisk.asset_id == Asset.id)
                             .where(Asset.status == LifecycleStatus.ACTIVE)).all()
    for asset in assets:
        score_asset(session, asset, trigger="kev_refresh")
    return len(assets)

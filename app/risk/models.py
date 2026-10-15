"""Stored risk assessments (decision E5): one row per finding, one summary row per asset.

Kept in their own tables, so the findings table of the Correlation module (and every
other existing table) stays unchanged - no migration needed.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base, UTCDateTime


class FindingRisk(Base):
    __tablename__ = "finding_risk"

    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    level: Mapped[str] = mapped_column(String(10), nullable=False)          # CRITICAL / HIGH / MEDIUM / LOW
    factors: Mapped[str] = mapped_column(Text, nullable=False)              # JSON list of scored factors
    unknown_factors: Mapped[str] = mapped_column(Text, nullable=False)      # JSON list
    why: Mapped[str] = mapped_column(Text, nullable=False)
    inputs: Mapped[str] = mapped_column(Text, nullable=False)               # JSON: what was scored
    model_version: Mapped[str] = mapped_column(String(10), nullable=False)
    assessed_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class AssetRisk(Base):
    """Risk of an asset = highest risk of its active findings (decisions E2, E4).

    No row = the asset was never assessed, which is not the same as "no risk".
    """

    __tablename__ = "asset_risk"

    asset_id: Mapped[str] = mapped_column(ForeignKey("asset_inventory.id"), primary_key=True)
    assessed_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    open_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    accepted_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_with_unknowns: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_score: Mapped[int | None] = mapped_column(Integer)
    max_level: Mapped[str | None] = mapped_column(String(10))
    correlation_warnings: Mapped[str] = mapped_column(Text, nullable=False, default="[]")   # JSON list
    model_version: Mapped[str] = mapped_column(String(10), nullable=False)


class AssetRiskHistory(Base):
    """One entry per change of an asset's risk (step 4: assessment history)."""

    __tablename__ = "asset_risk_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("asset_inventory.id"), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    # correlation / kev_refresh / finding_status / asset_change / rescore
    trigger: Mapped[str] = mapped_column(String(30), nullable=False)
    run_id: Mapped[int | None] = mapped_column(Integer)          # correlation_runs.id, when from a run
    max_score: Mapped[int | None] = mapped_column(Integer)
    max_level: Mapped[str | None] = mapped_column(String(10))
    open_findings: Mapped[int] = mapped_column(Integer, nullable=False)
    accepted_findings: Mapped[int] = mapped_column(Integer, nullable=False)
    correlation_warnings: Mapped[str] = mapped_column(Text, nullable=False, default="[]")   # JSON list
    model_version: Mapped[str] = mapped_column(String(10), nullable=False)

    __table_args__ = (Index("ix_asset_risk_history_asset", "asset_id", "id"),)

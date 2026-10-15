"""Daily organisation-level posture snapshots - the history behind the dashboard trends.

Current state alone cannot tell how the posture looked last month, and historical scores
must never be reconstructed from today's data. So the posture computed by
app.dashboard.service.posture() is persisted once per UTC day (the latest value of the
day wins), whenever assessments, KEV refreshes, finding status or asset changes update it.
"""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Date, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base, UTCDateTime


class SecuritySnapshot(Base):
    __tablename__ = "security_snapshots"

    day: Mapped[date] = mapped_column(Date, primary_key=True)                 # UTC calendar day
    taken_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)   # last update of the day
    security_score: Mapped[int | None] = mapped_column(Integer)               # None: nothing assessed
    method_version: Mapped[str] = mapped_column(String(10), nullable=False)
    worst_asset_risk: Mapped[int | None] = mapped_column(Integer)
    assets_active: Mapped[int] = mapped_column(Integer, nullable=False)
    assets_assessed: Mapped[int] = mapped_column(Integer, nullable=False)
    assets_at_risk: Mapped[int] = mapped_column(Integer, nullable=False)
    open_findings: Mapped[int] = mapped_column(Integer, nullable=False)
    open_critical: Mapped[int] = mapped_column(Integer, nullable=False)
    open_high: Mapped[int] = mapped_column(Integer, nullable=False)
    open_medium: Mapped[int] = mapped_column(Integer, nullable=False)
    open_low: Mapped[int] = mapped_column(Integer, nullable=False)
    open_unscored: Mapped[int] = mapped_column(Integer, nullable=False)

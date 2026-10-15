"""Vulnerability correlation data model (E5).

Findings reference `asset_inventory.id` and are never deleted - they are closed
(resolved / verified_fixed) and reopened as the scanned software changes.
"""
from __future__ import annotations

import enum
from datetime import date, datetime

from sqlalchemy import Date, Enum, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..assets.models import Asset
from ..database import Base, UTCDateTime, utcnow
from ..risk.models import FindingRisk
from ..ticketing.models import JiraTicket


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_REMEDIATION = "in_remediation"
    RESOLVED = "resolved"              # vulnerable software no longer detected
    VERIFIED_FIXED = "verified_fixed"  # ... and a remediation ticket existed
    ACCEPTED_RISK = "accepted_risk"


ACTIVE_STATUSES = frozenset({FindingStatus.OPEN, FindingStatus.IN_REMEDIATION, FindingStatus.ACCEPTED_RISK})
CLOSED_STATUSES = frozenset({FindingStatus.RESOLVED, FindingStatus.VERIFIED_FIXED})


class SoftwareSource(str, enum.Enum):
    SCAN = "scan"        # Nmap version scan (Monitoring)
    MANUAL = "manual"    # entered by an analyst


def _enum(cls: type[enum.Enum]) -> Enum:
    return Enum(cls, native_enum=False, create_constraint=True, validate_strings=True,
                length=32, values_callable=lambda e: [m.value for m in e],
                name=f"ck_{cls.__name__.lower()}")


class Cve(Base):
    __tablename__ = "cves"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # e.g. CVE-2011-2523
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    published: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_modified: Mapped[datetime | None] = mapped_column(UTCDateTime)
    cvss_version: Mapped[str | None] = mapped_column(String(5))
    cvss_score: Mapped[float | None]
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="UNKNOWN")
    known_exploited: Mapped[bool] = mapped_column(nullable=False, default=False)  # CISA KEV
    kev_date_added: Mapped[date | None] = mapped_column(Date)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    matches: Mapped[list[CveCpeMatch]] = relationship(back_populates="cve", cascade="all, delete-orphan")


class CveCpeMatch(Base):
    """One vulnerable CPE criterion of a CVE (from the NVD 'configurations')."""

    __tablename__ = "cve_cpe_matches"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    criteria: Mapped[str] = mapped_column(String(300), nullable=False)
    vendor: Mapped[str] = mapped_column(String(100), nullable=False)
    product: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100))  # None = any version ("*")
    cpe_update: Mapped[str | None] = mapped_column(String(100))
    version_start_including: Mapped[str | None] = mapped_column(String(100))
    version_start_excluding: Mapped[str | None] = mapped_column(String(100))
    version_end_including: Mapped[str | None] = mapped_column(String(100))
    version_end_excluding: Mapped[str | None] = mapped_column(String(100))
    # Part of an AND configuration ("X running on Y"): the platform condition is not checked.
    platform_dependent: Mapped[bool] = mapped_column(nullable=False, default=False)

    cve: Mapped[Cve] = relationship(back_populates="matches")

    __table_args__ = (
        Index("ix_cve_cpe_matches_vendor_product", "vendor", "product"),
        Index("ix_cve_cpe_matches_cve_id", "cve_id"),
    )


class ProductSync(Base):
    """When the CVEs of one vendor/product were last downloaded (NVD cache)."""

    __tablename__ = "nvd_product_syncs"

    vendor: Mapped[str] = mapped_column(String(100), primary_key=True)
    product: Mapped[str] = mapped_column(String(100), primary_key=True)
    last_synced: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    cve_count: Mapped[int] = mapped_column(nullable=False, default=0)


class FeedSync(Base):
    """Last successful refresh of a whole feed ('cisa_kev', 'nvd_modified')."""

    __tablename__ = "feed_syncs"

    name: Mapped[str] = mapped_column(String(50), primary_key=True)
    last_synced: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    item_count: Mapped[int] = mapped_column(nullable=False, default=0)


class KevEntry(Base):
    """CISA Known Exploited Vulnerabilities catalogue entry (cached for offline use)."""

    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    vendor_project: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    product: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    date_added: Mapped[date] = mapped_column(Date, nullable=False)
    due_date: Mapped[date | None] = mapped_column(Date)
    ransomware_use: Mapped[str] = mapped_column(String(20), nullable=False, default="Unknown")


class AssetSoftware(Base):
    """Software entered manually for an asset (e.g. not visible to a network scan)."""

    __tablename__ = "asset_software"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False)
    product: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100))
    cpe: Mapped[str | None] = mapped_column(String(300))  # optional "vendor:product" or CPE string
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(100))

    __table_args__ = (Index("ix_asset_software_asset_id", "asset_id"),)


class Finding(Base):
    """A CVE affecting a piece of software on an asset."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("asset_inventory.id"), nullable=False)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id"), nullable=False)
    product_key: Mapped[str] = mapped_column(String(201), nullable=False)  # CPE vendor:product
    software: Mapped[str] = mapped_column(String(200), nullable=False)     # as detected, for display
    version: Mapped[str | None] = mapped_column(String(100))               # as detected, incl. distro suffix
    port: Mapped[int | None]
    protocol: Mapped[str | None] = mapped_column(String(10))
    source: Mapped[SoftwareSource] = mapped_column(_enum(SoftwareSource), nullable=False)
    matched_cpe: Mapped[str] = mapped_column(String(300), nullable=False)
    confidence: Mapped[str] = mapped_column(String(10), nullable=False, default="high")  # high / low
    status: Mapped[FindingStatus] = mapped_column(_enum(FindingStatus), nullable=False, default=FindingStatus.OPEN)
    status_reason: Mapped[str | None] = mapped_column(Text)
    ticket_key: Mapped[str | None] = mapped_column(String(50))  # remediation ticket (E7)
    last_scan_id: Mapped[int | None]
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    status_changed_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    cve: Mapped[Cve] = relationship(lazy="joined")
    asset: Mapped[Asset] = relationship(lazy="joined")
    # stored risk assessment (app.risk), kept in its own table
    risk: Mapped[FindingRisk | None] = relationship(lazy="selectin", viewonly=True)
    # Jira ticket delivery record (app.ticketing), if a ticket was queued or created
    ticket: Mapped[JiraTicket | None] = relationship(lazy="selectin", viewonly=True)

    __table_args__ = (
        UniqueConstraint("asset_id", "cve_id", "product_key", name="uq_findings_asset_cve_product"),
        Index("ix_findings_asset_id", "asset_id"),
        Index("ix_findings_status", "status"),
    )

    @property
    def asset_name(self) -> str:
        return self.asset.name

    @property
    def jira_eligibility(self) -> dict:
        from ..ticketing.service import eligibility  # lazy: ticketing depends on these models
        return eligibility(self)


class CorrelationRun(Base):
    """Log of each correlation job."""

    __tablename__ = "correlation_runs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    trigger: Mapped[str] = mapped_column(String(20), nullable=False)  # manual / scan / scheduled
    # all = every active asset, selected = a subset (manual or after a scan); None = before 0005
    scope: Mapped[str | None] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="running")  # running/success/partial/failed
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    duration_seconds: Mapped[float | None]
    assets_processed: Mapped[int] = mapped_column(nullable=False, default=0)
    findings_opened: Mapped[int] = mapped_column(nullable=False, default=0)
    findings_reopened: Mapped[int] = mapped_column(nullable=False, default=0)
    findings_closed: Mapped[int] = mapped_column(nullable=False, default=0)
    unmapped_software: Mapped[str] = mapped_column(Text, nullable=False, default="")  # comma-separated
    warnings: Mapped[str] = mapped_column(Text, nullable=False, default="")

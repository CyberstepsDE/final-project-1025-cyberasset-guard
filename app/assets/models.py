"""Asset Management data model.

An Asset is a persistent security object with its own identity (UUID), ownership,
environment, criticality and lifecycle status. Future modules (monitoring scans,
services, vulnerability findings, remediation) will reference `asset_inventory.id`
via foreign keys - which is why assets are deactivated rather than deleted.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Enum, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base, UTCDateTime, utcnow


class AssetType(str, enum.Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    VIRTUAL_MACHINE = "virtual_machine"
    CONTAINER = "container"
    NETWORK_DEVICE = "network_device"
    DATABASE = "database"
    WEB_APPLICATION = "web_application"
    CLOUD_RESOURCE = "cloud_resource"
    OTHER = "other"


class Environment(str, enum.Enum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class Criticality(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InternetFacing(str, enum.Enum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


class LifecycleStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"


def _enum(cls: type[enum.Enum]) -> Enum:
    """Store enum *values* as VARCHAR + CHECK constraint (portable, readable in SQLite)."""
    return Enum(cls, native_enum=False, create_constraint=True, validate_strings=True,
                length=32, values_callable=lambda e: [m.value for m in e],
                name=f"ck_{cls.__name__.lower()}")


class Asset(Base):
    __tablename__ = "asset_inventory"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    asset_type: Mapped[AssetType] = mapped_column(_enum(AssetType), nullable=False)
    environment: Mapped[Environment] = mapped_column(_enum(Environment), nullable=False)
    criticality: Mapped[Criticality] = mapped_column(_enum(Criticality), nullable=False)
    internet_facing: Mapped[InternetFacing] = mapped_column(
        _enum(InternetFacing), nullable=False, default=InternetFacing.UNKNOWN)
    status: Mapped[LifecycleStatus] = mapped_column(
        _enum(LifecycleStatus), nullable=False, default=LifecycleStatus.ACTIVE)

    ip_address: Mapped[str | None] = mapped_column(String(45))     # IPv4 or IPv6, normalized
    hostname: Mapped[str | None] = mapped_column(String(253))
    owner: Mapped[str | None] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    deactivated_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    tag_rows: Mapped[list[AssetTag]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin",
        order_by="AssetTag.tag")

    __table_args__ = (
        Index("ix_asset_inventory_name", "name"),
        Index("ix_asset_inventory_ip_address", "ip_address"),
        Index("ix_asset_inventory_hostname", "hostname"),
        Index("ix_asset_inventory_status", "status"),
    )

    @property
    def tags(self) -> list[str]:
        return sorted(t.tag for t in self.tag_rows)

    def set_tags(self, tags: list[str]) -> None:
        """Replace the tag set, keeping rows for tags that stay (no churn)."""
        wanted = list(dict.fromkeys(tags))
        self.tag_rows = [t for t in self.tag_rows if t.tag in wanted]
        existing = {t.tag for t in self.tag_rows}
        self.tag_rows.extend(AssetTag(tag=t) for t in wanted if t not in existing)


class AssetTag(Base):
    """Tags in their own table (not a serialized string) so they can be filtered and indexed."""

    __tablename__ = "asset_tags"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False)
    tag: Mapped[str] = mapped_column(String(50), nullable=False)

    asset: Mapped[Asset] = relationship(back_populates="tag_rows")

    __table_args__ = (
        UniqueConstraint("asset_id", "tag", name="uq_asset_tags_asset_tag"),
        Index("ix_asset_tags_tag", "tag"),
    )

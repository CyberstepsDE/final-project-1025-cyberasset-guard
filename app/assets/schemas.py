"""API schemas for Asset Management (kept separate from the ORM model)."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import AssetType, Criticality, Environment, InternetFacing, LifecycleStatus

# Human-readable labels for the controlled vocabularies (used by the UI via /assets/options).
LABELS: dict[str, dict[str, str]] = {
    "asset_type": {
        "server": "Server", "workstation": "Workstation", "laptop": "Laptop",
        "virtual_machine": "Virtual Machine", "container": "Container",
        "network_device": "Network Device", "database": "Database",
        "web_application": "Web Application", "cloud_resource": "Cloud Resource",
        "other": "Other",
    },
    "environment": {"development": "Development", "test": "Test", "staging": "Staging",
                    "production": "Production"},
    "criticality": {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"},
    "internet_facing": {"yes": "Yes", "no": "No", "unknown": "Unknown"},
    "status": {"active": "Active", "inactive": "Inactive"},
}

NAME_MAX, OWNER_MAX, DESCRIPTION_MAX = 200, 200, 5000
MAX_TAGS, TAG_MAX = 20, 50
_HOSTNAME_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_TAG = re.compile(r"^[\w][\w .:/-]*$")


def _blank_to_none(value: Any) -> Any:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return value


def _validate_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError("must be a valid IPv4 or IPv6 address") from None


def _validate_hostname(value: str | None) -> str | None:
    if value is None:
        return None
    host = value.lower().rstrip(".")
    if len(host) > 253 or not all(_HOSTNAME_LABEL.match(label) for label in host.split(".")):
        raise ValueError("must be a valid hostname (letters, digits, hyphens; labels of 1-63 characters)")
    return host


def _validate_tags(value: list[str] | None) -> list[str]:
    if value is None:
        return []
    tags: list[str] = []
    for raw in value:
        tag = raw.strip().lower() if isinstance(raw, str) else raw
        if not tag:
            continue
        if not isinstance(tag, str) or len(tag) > TAG_MAX or not _TAG.match(tag):
            raise ValueError(f"tag '{raw}' is invalid: use up to {TAG_MAX} letters, digits, "
                             "spaces or . : / - _")
        if tag not in tags:
            tags.append(tag)
    if len(tags) > MAX_TAGS:
        raise ValueError(f"at most {MAX_TAGS} tags are allowed")
    return sorted(tags)


Name = Annotated[str, Field(min_length=1, max_length=NAME_MAX, examples=["web-prod-01"])]


class _AssetFields(BaseModel):
    """Field definitions and validators shared by create and update."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ip_address: str | None = Field(None, max_length=45, examples=["192.168.10.20"])
    hostname: str | None = Field(None, max_length=253, examples=["web01.corp.example"])
    owner: str | None = Field(None, max_length=OWNER_MAX, examples=["Platform Team"])
    description: str | None = Field(None, max_length=DESCRIPTION_MAX,
                                    description="Business description / purpose of the asset")

    @field_validator("ip_address", "hostname", "owner", "description", mode="before")
    @classmethod
    def _empty_optional(cls, v):
        return _blank_to_none(v)

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v):
        return _validate_ip(v)

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v):
        return _validate_hostname(v)


class AssetCreate(_AssetFields):
    name: Name
    asset_type: AssetType
    environment: Environment
    criticality: Criticality
    internet_facing: InternetFacing = InternetFacing.UNKNOWN
    tags: list[str] = Field(default_factory=list, examples=[["dmz", "pci"]])

    @field_validator("name", mode="before")
    @classmethod
    def _name(cls, v):
        if isinstance(v, str) and not v.strip():
            raise ValueError("asset name must not be empty")
        return v

    @field_validator("tags", mode="before")
    @classmethod
    def _tags(cls, v):
        return _validate_tags(v)


class AssetUpdate(_AssetFields):
    """Partial update. Omitted fields stay unchanged; null clears an optional field.
    The identifier and creation timestamp can never be changed."""

    name: Name | None = None
    asset_type: AssetType | None = None
    environment: Environment | None = None
    criticality: Criticality | None = None
    internet_facing: InternetFacing | None = None
    status: LifecycleStatus | None = None
    tags: list[str] | None = None

    @field_validator("name", mode="before")
    @classmethod
    def _name(cls, v):
        if isinstance(v, str) and not v.strip():
            raise ValueError("asset name must not be empty")
        return v

    @field_validator("tags", mode="before")
    @classmethod
    def _tags(cls, v):
        return None if v is None else _validate_tags(v)

    @model_validator(mode="after")
    def _required_not_null(self):
        for field in ("name", "asset_type", "environment", "criticality", "internet_facing", "status"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be null")
        return self


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(description="Stable unique identifier (UUID), independent of IP / hostname")
    name: str
    asset_type: AssetType
    environment: Environment
    criticality: Criticality
    internet_facing: InternetFacing
    status: LifecycleStatus
    ip_address: str | None
    hostname: str | None
    owner: str | None
    description: str | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime
    deactivated_at: datetime | None


class AssetList(BaseModel):
    items: list[AssetRead]
    total: int = Field(description="Number of assets matching the filters (before paging)")
    limit: int
    offset: int


class Option(BaseModel):
    value: str
    label: str


class AssetOptions(BaseModel):
    """Controlled vocabularies with display labels - single source of truth for clients."""

    asset_type: list[Option]
    environment: list[Option]
    criticality: list[Option]
    internet_facing: list[Option]
    status: list[Option]

    @classmethod
    def build(cls) -> AssetOptions:
        return cls(**{field: [Option(value=v, label=lbl) for v, lbl in labels.items()]
                      for field, labels in LABELS.items()})

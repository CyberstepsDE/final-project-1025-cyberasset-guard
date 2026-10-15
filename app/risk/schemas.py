"""API schemas for stored risk assessments."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


class FindingRiskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    score: int = Field(description="0-100, contextual risk (not CVSS alone)")
    level: str = Field(description="CRITICAL / HIGH / MEDIUM / LOW")
    why: str
    factors: list[dict]
    unknown_factors: list[str] = Field(description="Inputs that were unknown and scored conservatively")
    inputs: dict
    model_version: str
    assessed_at: datetime

    @field_validator("factors", "unknown_factors", "inputs", mode="before")
    @classmethod
    def _parse_json(cls, value: Any) -> Any:
        return _json(value)


class AssetRiskHistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    recorded_at: datetime
    trigger: str = Field(description="correlation / kev_refresh / finding_status / asset_change / rescore")
    run_id: int | None = Field(description="Correlation run that produced the change")
    max_score: int | None
    max_level: str | None
    open_findings: int
    accepted_findings: int
    correlation_warnings: list[str] = []
    model_version: str

    @field_validator("correlation_warnings", mode="before")
    @classmethod
    def _parse_json(cls, value: Any) -> Any:
        return _json(value)


class AssetRiskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_id: str
    asset_status: str | None = Field(None, description="active / inactive - inactive assets are no "
                                                       "longer reassessed; exclude them from totals")
    assessed: bool = Field(True, description="false = never assessed (not: no risk)")
    assessed_at: datetime | None = None
    open_findings: int = 0
    accepted_findings: int = 0
    findings_with_unknowns: int = 0
    max_score: int | None = Field(None, description="Highest risk of the open findings; null = none")
    max_level: str | None = None
    correlation_warnings: list[str] = []
    model_version: str | None = None

    @field_validator("correlation_warnings", mode="before")
    @classmethod
    def _parse_json(cls, value: Any) -> Any:
        return _json(value)

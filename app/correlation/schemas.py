from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from ..risk.schemas import FindingRiskRead
from ..ticketing.schemas import Eligibility, TicketRead
from .models import FindingStatus, SoftwareSource


class CveRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    description: str
    published: datetime | None
    cvss_version: str | None
    cvss_score: float | None
    cvss_vector: str | None
    severity: str
    known_exploited: bool = Field(description="Listed in the CISA KEV catalogue")
    kev_date_added: date | None

    @computed_field
    @property
    def nvd_url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.id}"


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: str
    asset_name: str
    software: str
    version: str | None
    port: int | None
    protocol: str | None
    source: SoftwareSource
    matched_cpe: str
    confidence: str = Field(description="'low' when the version is unknown or the CVE needs a specific platform")
    status: FindingStatus
    status_reason: str | None
    ticket_key: str | None
    first_seen: datetime
    last_seen: datetime
    status_changed_at: datetime
    resolved_at: datetime | None
    cve: CveRead
    risk: FindingRiskRead | None = Field(None, description="Contextual risk; null until the asset is assessed")
    ticket: TicketRead | None = Field(None, description="Jira ticket delivery state; null when none was queued")
    jira_eligibility: Eligibility | None = Field(None, description="Whether a Jira task qualifies, and why (not)")


class FindingList(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[FindingRead]


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    reason: str | None = Field(None, max_length=1000, description="Required when accepting a risk")
    ticket_key: str | None = Field(None, max_length=50, examples=["ASSET-123"])


class SoftwareCreate(BaseModel):
    product: str = Field(min_length=1, max_length=200, examples=["OpenSSH"])
    version: str | None = Field(None, max_length=100, examples=["8.2p1"])
    cpe: str | None = Field(None, max_length=300, description="Optional 'vendor:product' or CPE when the "
                                                              "product name is not in the catalogue",
                            examples=["openbsd:openssh"])

    @field_validator("product", "version", "cpe", mode="before")
    @classmethod
    def _strip(cls, v):
        return v.strip() or None if isinstance(v, str) else v


class SoftwareRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    product: str
    version: str | None
    cpe: str | None
    created_at: datetime
    created_by: str | None


class RunRequest(BaseModel):
    asset_ids: list[str] | None = Field(None, max_length=1000, description="Omit to correlate all active assets")


class CorrelationRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    trigger: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    duration_seconds: float | None
    assets_processed: int
    findings_opened: int
    findings_reopened: int
    findings_closed: int
    unmapped_software: str
    warnings: str


class ScheduleStatus(BaseModel):
    """When assessments run and how current the vulnerability data is (step 4)."""

    periodic_enabled: bool = Field(description="false when CAG_CORRELATION_INTERVAL_HOURS=0")
    interval_hours: int
    next_run_at: datetime | None = Field(description="Next periodic run; null when not scheduled in this process")
    after_scan: bool = Field(description="Assets are re-assessed after each completed version scan")
    nvd_api_key_configured: bool
    kev_last_synced: datetime | None
    kev_entries: int | None
    kev_current: bool = Field(description="KEV catalogue younger than 48 h - otherwise KEV status counts "
                                          "as unknown in the risk score")
    active_run: CorrelationRunRead | None
    last_run: CorrelationRunRead | None

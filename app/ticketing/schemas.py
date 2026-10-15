from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class TicketRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    state: str = Field(description="pending | sending | failed | error | created | skipped")
    trigger: str = Field(description="auto (qualification policy) or manual")
    requested_by: str | None
    issue_key: str | None
    issue_url: str | None
    jira_status: str | None = Field(description="Last known Jira status (refresh with POST .../ticket/sync)")
    attempts: int
    next_attempt_at: datetime | None
    last_attempt_at: datetime | None
    last_error: str | None
    error_category: str | None = Field(description="authentication | permission | invalid_project | "
                                       "invalid_request | rate_limited | network | timeout | server | "
                                       "malformed | config")
    synced_at: datetime | None
    created_at: datetime


class Eligibility(BaseModel):
    automatic: bool = Field(description="Qualifies for an automatic Jira task under the current policy")
    manual: bool = Field(description="An analyst may create a task by hand")
    reason: str
    manual_reason: str | None


class TicketRequestResult(BaseModel):
    queued: bool = Field(description="False when the issue already exists or is being created")
    ticket: TicketRead


class IntegrationStatus(BaseModel):
    state: str = Field(description="disabled | misconfigured | enabled")
    problem: str | None
    base_url: str | None
    project_key: str | None
    issue_type: str
    label: str
    max_retries: int
    policy: dict
    tickets: dict[str, int]
    last_error: str | None

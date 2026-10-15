"""Finding qualification: which findings get a Jira task.

A finding is the incident unit of CyberAsset Guard (one CVE on one product of one asset);
there is no separate incident model. The decision uses the Risk Engine's stored level
(app.risk) - there is no second scoring. Configured via CAG_JIRA_* (see app.config).

Base checks (automatic AND manual tasks):
  * the finding is open or in remediation (not accepted, not resolved),
  * its asset is active,
  * it has a risk assessment (nothing to prioritise otherwise),
  * no ticket was linked to it by hand (finding.ticket_key).
Automatic tasks additionally need
  * CAG_JIRA_AUTO_CREATE=true,
  * a risk level >= CAG_JIRA_MIN_SEVERITY (default HIGH: CRITICAL and HIGH qualify,
    MEDIUM and LOW do not),
  * high confidence - a low-confidence correlation is a *potential* finding that requires
    validation, unless CAG_JIRA_INCLUDE_LOW_CONFIDENCE=true.
A manual task (analyst, findings:write) needs only the base checks: the analyst takes the
prioritisation decision. Its classification is stated in the task, never upgraded.
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import config

OPEN_STATUSES = ("open", "in_remediation")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass(frozen=True)
class Policy:
    auto_create: bool = True
    min_severity: str = "HIGH"
    include_low_confidence: bool = False

    @classmethod
    def from_config(cls) -> Policy:
        return cls(config.JIRA_AUTO_CREATE, config.JIRA_MIN_SEVERITY, config.JIRA_INCLUDE_LOW_CONFIDENCE)

    def describe(self) -> dict:
        levels = list(SEVERITIES[SEVERITIES.index(self.min_severity):])[::-1]
        return {"auto_create": self.auto_create, "min_severity": self.min_severity, "levels": levels,
                "include_low_confidence": self.include_low_confidence, "finding_statuses": list(OPEN_STATUSES)}


def classification(status: str, confidence: str) -> str:
    """How certain the finding is - stated in the task, never upgraded."""
    if status in ("resolved", "verified_fixed"):
        return "resolved"
    if confidence == "high":
        return "confirmed version match"      # the detected version is in the CVE's affected range
    return "potential - requires validation"  # version unknown or platform-specific CVE


def qualifies(policy: Policy, *, status: str, asset_active: bool, level: str | None, confidence: str,
              has_manual_ticket: bool, manual: bool = False) -> tuple[bool, str]:
    """(qualifies, reason) - the reason is shown to analysts and written to the audit log."""
    if status not in OPEN_STATUSES:
        return False, f"finding is {status.replace('_', ' ')}"
    if not asset_active:
        return False, "asset is inactive"
    if has_manual_ticket:
        return False, "a ticket is already linked"
    if level is None:
        return False, "finding has no risk assessment yet"
    if manual:
        return True, "requested by an analyst"
    if not policy.auto_create:
        return False, "automatic task creation is off (CAG_JIRA_AUTO_CREATE=false)"
    if level not in SEVERITIES or SEVERITIES.index(level) < SEVERITIES.index(policy.min_severity):
        return False, f"risk level {level} is below {policy.min_severity}"
    if confidence != "high" and not policy.include_low_confidence:
        return False, "potential finding - requires validation before a task is created automatically"
    return True, f"risk level {level} (>= {policy.min_severity})"

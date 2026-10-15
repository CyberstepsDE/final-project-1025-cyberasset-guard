"""Jira task content for a finding: summary, labels, priority and an Atlassian Document Format
(ADF) description.

Only data that exists in CyberAsset Guard is included - nothing is invented; missing values
are omitted or shown as "unknown". All values (scanner output, host names, CVE text, asset
metadata) are untrusted and go into ADF *text* nodes, which Jira renders literally - no
markup can be injected. The only links are built here from validated values (NVD URL from
a CVE id that matches the CVE pattern, the configured https CAG_PUBLIC_URL).
"""
from __future__ import annotations

import json
import re
from typing import Any

from .. import config
from .policy import classification

SUMMARY_MAX = 255
APP_LABEL = "cyberasset-guard"
# Risk level -> Jira's default priority names; used only if the project offers that priority.
PRIORITY_BY_LEVEL = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")


# --- ADF helpers ---------------------------------------------------------------------------------

def _text(value: Any, *, link: str | None = None, strong: bool = False, code: bool = False) -> dict:
    node: dict[str, Any] = {"type": "text", "text": str(value)[:2000] or "-"}
    marks: list[dict] = []
    if strong:
        marks.append({"type": "strong"})
    if code:
        marks.append({"type": "code"})
    if link:
        marks.append({"type": "link", "attrs": {"href": link}})
    if marks:
        node["marks"] = marks
    return node


def _para(*parts: dict) -> dict:
    return {"type": "paragraph", "content": list(parts)}


def _heading(text: str) -> dict:
    return {"type": "heading", "attrs": {"level": 3}, "content": [_text(text)]}


def _rows(rows: list[tuple[str, Any]]) -> dict:
    """'Label: value' lines; rows whose value is None are left out (not available)."""
    items = [{"type": "listItem", "content": [_para(_text(f"{label}: ", strong=True), _text(value))]}
             for label, value in rows if value is not None and value != ""]
    return {"type": "bulletList", "content": items or [{"type": "listItem", "content": [_para(_text("-"))]}]}


def doc(*blocks: dict) -> dict:
    return {"type": "doc", "version": 1, "content": list(blocks)}


def note(text: str) -> dict:
    return doc(_para(_text(text)))


# --- content -------------------------------------------------------------------------------------

def _iso(value) -> str | None:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else None


def level(finding) -> str:
    return finding.risk.level if finding.risk else "UNASSESSED"


def summary(finding) -> str:
    software = f"{finding.software} {finding.version}" if finding.version else finding.software
    text = f"[{level(finding)}] {finding.cve_id} in {software} – {finding.asset.name}"
    text = " ".join(text.split())                        # no line breaks from untrusted values
    return text if len(text) <= SUMMARY_MAX else text[:SUMMARY_MAX - 1] + "…"


def labels(ticket_label: str, label: str) -> list[str]:
    return [label, APP_LABEL, ticket_label]


def _factors(risk) -> list[dict]:
    try:
        factors = json.loads(risk.factors) if risk else []
    except ValueError:
        return []
    return [f for f in factors if isinstance(f, dict)]


def _app_link(finding) -> str | None:
    """Link to the asset page (its findings and risk panel); only with an https CAG_PUBLIC_URL."""
    if not config.PUBLIC_URL or not config.PUBLIC_URL.startswith("https://"):
        return None
    return f"{config.PUBLIC_URL}/#/assets/{finding.asset_id}"


def description(finding) -> dict:
    asset, cve, risk = finding.asset, finding.cve, finding.risk
    kind = classification(finding.status.value, finding.confidence)
    nvd = f"https://nvd.nist.gov/vuln/detail/{cve.id}" if _CVE_ID.fullmatch(cve.id or "") else None

    blocks: list[dict] = [_para(_text(
        "Created by CyberAsset Guard for a qualifying security finding. The finding in CyberAsset Guard "
        "remains the source of truth; this task tracks its remediation."))]

    blocks += [_heading("Security Finding"), _rows([
        ("Finding ID", f"{finding.id} (CyberAsset Guard)"),
        ("Classification", kind),
        ("Severity", level(finding)),
        ("Risk Score", f"{risk.score}/100" if risk else "not assessed"),
        ("Asset", f"{asset.name} ({asset.id})"),
        ("Detected At", _iso(finding.first_seen)),
        ("Last Seen", _iso(finding.last_seen)),
        ("CVE", cve.id or "not applicable"),
        ("Finding Status", finding.status.value.replace("_", " ")),
    ])]
    if kind != "confirmed version match":
        blocks.append(_para(_text("Requires validation: ", strong=True), _text(
            "the detected version is unknown or the CVE applies only to specific platforms. Confirm that the "
            "asset is affected before remediating.")))

    service = f"{finding.software} {finding.version or '(version unknown)'}"
    if finding.port:
        service += f" on {finding.protocol or 'tcp'}/{finding.port}"
    source = (f"network version scan #{finding.last_scan_id}" if finding.last_scan_id else "network version scan") \
        if finding.source.value == "scan" else "software entered manually on the asset"
    blocks += [_heading("Technical Evidence"), _rows([
        ("Detected software", service),
        ("Detection source", source),
        ("Matched CPE", finding.matched_cpe),
        ("CVSS base score", f"{cve.cvss_score} (CVSS v{cve.cvss_version})" if cve.cvss_score is not None
         else "unknown"),
        ("CVSS vector", cve.cvss_vector),
        ("CVE severity", cve.severity),
        ("Known exploited (CISA KEV)", f"yes, listed {cve.kev_date_added}" if cve.known_exploited else "no"),
    ])]
    if nvd:
        blocks.append(_para(_text("NVD entry: ", strong=True), _text(cve.id, link=nvd)))
    if cve.description:
        blocks.append(_para(_text("CVE description: ", strong=True), _text(cve.description[:1500])))

    blocks += [_heading("Context and Risk Explanation"), _rows([
        ("Environment", asset.environment.value),
        ("Business criticality", asset.criticality.value),
        ("Internet-facing", asset.internet_facing.value),
        ("Hostname", asset.hostname),
        ("IP address", asset.ip_address),
    ])]
    if risk:
        blocks.append(_para(_text(risk.why)))
        blocks.append(_rows([(str(f.get("label", f.get("key"))),
                              f"{f.get('points')}/{f.get('max_points')} points - {f.get('reason')}")
                             for f in _factors(risk)]))
        try:
            unknown = json.loads(risk.unknown_factors or "[]")
        except ValueError:
            unknown = []
        if unknown:
            blocks.append(_para(_text("Unknown inputs (scored conservatively): ", strong=True),
                                _text(", ".join(map(str, unknown)))))
    else:
        blocks.append(_para(_text("The asset has not been risk-assessed yet.")))

    blocks += [_heading("Recommended Remediation"), _para(_text(
        f"Update {finding.software} on {asset.name} to a version that is not affected by {cve.id}, following "
        "the vendor advisory linked from the NVD entry, or apply the vendor's mitigation. If the risk is "
        "accepted instead, record that decision and its reason on the finding in CyberAsset Guard."))]

    blocks += [_heading("Verification Criteria"), _rows([
        ("1", f"Run a version scan of {asset.name} in CyberAsset Guard after the change."),
        ("2", "The scan reports the same product on the same port with a version that is not affected, "
              "checked against current CVE data."),
        ("3", "CyberAsset Guard then marks the finding 'verified fixed' and adds a comment to this task. "
              "Close the task according to your Jira workflow."),
        ("If it recurs", "a later scan that detects a vulnerable version again reopens the finding and "
                         "comments on this same task - no new task is created."),
    ])]

    link = _app_link(finding)
    if link:
        blocks.append(_para(_text("Open the asset in CyberAsset Guard", link=link)))
    return doc(*blocks)


def fields(finding, ticket_label: str, settings, meta) -> dict:
    data: dict[str, Any] = {
        "project": {"key": settings.project_key},
        "issuetype": {"id": meta.issue_type_id},
        "summary": summary(finding),
        "description": description(finding),
        "labels": labels(ticket_label, settings.label),
    }
    priority = PRIORITY_BY_LEVEL.get(level(finding))
    if priority and priority in meta.priorities:
        data["priority"] = {"name": priority}
    if settings.assignee and "assignee" in meta.fields:
        data["assignee"] = {"accountId": settings.assignee}
    return data

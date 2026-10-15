"""Pick the best CVSS score from an NVD CVE record."""
from dataclasses import dataclass

# Newest CVSS version first.
_METRIC_KEYS = [
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
]


@dataclass(frozen=True)
class CvssInfo:
    version: str | None
    score: float | None
    vector: str | None
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / NONE / UNKNOWN


UNKNOWN = CvssInfo(None, None, None, "UNKNOWN")


def severity_from_score(score: float, version: str) -> str:
    if version == "2.0":
        return "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
    if score == 0:
        return "NONE"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def extract_cvss(cve: dict) -> CvssInfo:
    """Use the newest CVSS version present, preferring NVD's own ("Primary") score."""
    metrics = cve.get("metrics") or {}
    for key, version in _METRIC_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        # CVSS v2 keeps baseSeverity on the entry, v3/v4 inside cvssData.
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return CvssInfo(
            version=version,
            score=float(score),
            vector=data.get("vectorString"),
            severity=(severity or severity_from_score(float(score), version)).upper(),
        )
    return UNKNOWN

"""Risk Engine - explainable, context-aware risk score (0-100) for one vulnerability finding.

The score is the sum of five transparent factors, so every number can be
explained to an analyst ("WHY is this critical?"):

  factor          max  driven by
  severity         40  CVSS base score (cvss * 4)
  exposure         20  asset internet_facing (yes / no), halved if a scan showed
                       the affected service is not reachable
  criticality      15  business criticality of the asset
  environment      10  production / staging / test / development
  exploitability   15  CISA KEV (actively exploited) or public exploit code

Levels: CRITICAL >= 85, HIGH >= 65, MEDIUM >= 40, otherwise LOW.

Unknown inputs are an explicit state, never a silent default. They are scored
conservatively (see UNKNOWN_*), listed in `unknown_factors` and named in the
reasons, so missing data never makes a finding look harmless:
  * CVSS unknown              -> assumed 7.0 (28 points)
  * internet_facing unknown   -> scored as internet-facing (20 points)
  * reachability unknown      -> exposure is not halved
  * KEV / exploit unknown     -> scored as a public exploit (10 points)

The engine is a pure function: no database, network, clock or randomness. The
same input always gives the same result. CVSS has one decimal place (as published),
so every factor is an exact number of tenths; the total is rounded half-up once.

Example from the design: OpenSSH 8.2 (CVSS 9.8) on port 22, internet-facing,
critical production asset, public exploit -> 39.2+20+15+10+10 = 94 CRITICAL.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from decimal import Decimal
from enum import Enum
from typing import Any

MODEL_VERSION = "1"

SEVERITY_MAX = 40
EXPOSURE_POINTS = {"yes": 20, "no": 8}
CRITICALITY_POINTS = {"critical": 15, "high": 10, "medium": 6, "low": 2}
ENVIRONMENT_POINTS = {"production": 10, "staging": 5, "test": 2, "development": 2}
EXPLOIT_POINTS = {"known_exploited": 15, "public_exploit": 10, "none": 0}
LEVELS = ((85, "CRITICAL"), (65, "HIGH"), (40, "MEDIUM"), (0, "LOW"))

UNKNOWN = "unknown"
UNKNOWN_CVSS = 7.0                               # conservative assumption, not a "medium" default
UNKNOWN_EXPOSURE_POINTS = EXPOSURE_POINTS["yes"]
UNKNOWN_EXPLOIT_POINTS = EXPLOIT_POINTS["public_exploit"]

TRI_STATE = ("yes", "no", UNKNOWN)
REACHABILITY = ("open", "not_open", UNKNOWN)     # from the latest scan of the affected port

_LABELS = {"cvss": "CVSS score", "internet_facing": "internet exposure",
           "reachability": "service reachability", "kev": "CISA KEV status",
           "public_exploit": "public exploit status"}


class RiskInputError(ValueError):
    """An input is outside the values the model defines."""


@dataclass(frozen=True)
class RiskFactor:
    key: str
    label: str
    value: str          # the value that was actually scored ("unknown" when unknown)
    points: float
    max_points: int
    known: bool
    reason: str


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    factors: tuple[RiskFactor, ...]
    unknown_factors: tuple[str, ...]
    why: str
    model_version: str = MODEL_VERSION

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- input validation ----------------------------------------------------------------------------

def _value(name: str, raw: Any, allowed) -> str:
    """Accept plain strings and str-based enums (e.g. app.assets.models.Criticality)."""
    value = raw.value if isinstance(raw, Enum) else raw
    if not isinstance(value, str) or value not in allowed:
        raise RiskInputError(f"{name} must be one of {sorted(allowed)}, got {raw!r}")
    return str.__str__(value)                       # a plain str, never a subclass instance


def _cvss(raw: Any) -> Decimal | None:
    """CVSS base score: 0.0-10.0 with at most one decimal place (as published). int, float, Decimal."""
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float, Decimal)):
        raise RiskInputError(f"cvss must be a number between 0 and 10 or None, got {raw!r}")
    try:
        value = Decimal(str(raw)) if isinstance(raw, float) else Decimal(raw)
        valid = value.is_finite() and 0 <= value <= 10 and value == value.quantize(Decimal("0.1"))
    except ArithmeticError:                          # e.g. huge ints, invalid Decimal operations
        valid = False
    if not valid:
        raise RiskInputError(f"cvss must be between 0 and 10 with at most one decimal place, got {raw!r}")
    return abs(value.quantize(Decimal("0.1")))      # abs(): -0.0 -> 0.0


def _port(raw: Any) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int) or not 1 <= raw <= 65535:
        raise RiskInputError(f"port must be between 1 and 65535 or None, got {raw!r}")
    return raw


def level_for(score: int) -> str:
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise RiskInputError(f"score must be between 0 and 100, got {score!r}")
    return next(level for threshold, level in LEVELS if score >= threshold)


def model() -> dict[str, Any]:
    """The scoring model, for transparency (exposed via the API later). A fresh copy per call."""
    return {
        "model_version": MODEL_VERSION,
        "severity_max": SEVERITY_MAX,
        "exposure": dict(EXPOSURE_POINTS),
        "criticality": dict(CRITICALITY_POINTS),
        "environment": dict(ENVIRONMENT_POINTS),
        "exploitability": dict(EXPLOIT_POINTS),
        "levels": {level: threshold for threshold, level in LEVELS},
        "unknown": {"cvss_assumed": UNKNOWN_CVSS, "exposure_points": UNKNOWN_EXPOSURE_POINTS,
                    "exploitability_points": UNKNOWN_EXPLOIT_POINTS,
                    "reachability": "exposure not halved"},
    }


# --- scoring -------------------------------------------------------------------------------------

def assess(*, cvss: float | Decimal | None, internet_facing: str, criticality: str, environment: str,
           kev: str = UNKNOWN, public_exploit: str = UNKNOWN, reachability: str = UNKNOWN,
           port: int | None = None) -> RiskAssessment:
    """Score one finding. Raises RiskInputError for values the model does not define.

    cvss            CVSS base score 0.0-10.0 with one decimal place (int / float / Decimal),
                    or None when not (yet) published
    internet_facing asset field: "yes" / "no" / "unknown"
    criticality     asset field: "low" / "medium" / "high" / "critical"
    environment     asset field: "development" / "test" / "staging" / "production"
    kev             listed in CISA KEV: "yes" / "no" / "unknown"
    public_exploit  public exploit code referenced: "yes" / "no" / "unknown"
    reachability    latest scan of the affected port: "open" / "not_open" / "unknown"
    port            affected port, for the explanation only
    """
    cvss = _cvss(cvss)
    internet_facing = _value("internet_facing", internet_facing, TRI_STATE)
    criticality = _value("criticality", criticality, CRITICALITY_POINTS)
    environment = _value("environment", environment, ENVIRONMENT_POINTS)
    kev = _value("kev", kev, TRI_STATE)
    public_exploit = _value("public_exploit", public_exploit, TRI_STATE)
    reachability = _value("reachability", reachability, REACHABILITY)
    port = _port(port)

    factors: list[tuple[RiskFactor, int]] = []      # (factor, points in tenths)
    unknown: list[str] = []
    drivers: list[str] = []

    def add(key, label, value, tenths, max_points, known, reason):
        factors.append((RiskFactor(key, label, value, tenths / 10, max_points, known, reason), tenths))

    # Severity
    if cvss is None:
        unknown.append("cvss")
        add("severity", "Severity (CVSS)", UNKNOWN, int(Decimal(str(UNKNOWN_CVSS)) * SEVERITY_MAX),
            SEVERITY_MAX, False, f"CVSS score unknown - scored conservatively as {UNKNOWN_CVSS}")
    else:
        # one decimal place * 4 -> an exact number of tenths, so the only rounding is the final one
        add("severity", "Severity (CVSS)", str(cvss), int(cvss * SEVERITY_MAX), SEVERITY_MAX, True,
            f"CVSS base score {cvss}")
        if cvss >= 9:
            drivers.append(f"critical CVSS {cvss}")
        elif cvss >= 7:
            drivers.append(f"high CVSS {cvss}")

    # Exposure
    where = f" on port {port}" if port else ""
    if internet_facing == UNKNOWN:
        unknown.append("internet_facing")
        exposure_tenths = UNKNOWN_EXPOSURE_POINTS * 10
        reason = "Internet exposure unknown - scored as internet-facing"
    elif internet_facing == "yes":
        exposure_tenths = EXPOSURE_POINTS["yes"] * 10
        reason = "Internet-facing asset"
    else:
        exposure_tenths = EXPOSURE_POINTS["no"] * 10
        reason = "Not internet-facing (internal network)"
    if reachability == "open":
        reason += f", service reachable{where}"
        if internet_facing == "yes":
            drivers.append(f"internet exposure (port {port})" if port else "internet exposure")
    elif reachability == "not_open":
        exposure_tenths //= 2
        reason += f", service not reachable{where} in the latest scan - halved"
    else:
        unknown.append("reachability")
        reason += ", reachability not confirmed by a scan - not reduced"
        if internet_facing == "yes":
            drivers.append("internet-facing asset")
    add("exposure", "Exposure", internet_facing, exposure_tenths, EXPOSURE_POINTS["yes"],
        internet_facing != UNKNOWN and reachability != UNKNOWN, reason)

    # Business criticality + environment
    add("criticality", "Asset criticality", criticality, CRITICALITY_POINTS[criticality] * 10,
        max(CRITICALITY_POINTS.values()), True, f"Asset is classified as {criticality} for the business")
    add("environment", "Environment", environment, ENVIRONMENT_POINTS[environment] * 10,
        max(ENVIRONMENT_POINTS.values()), True, f"Runs in {environment}")
    if criticality in ("critical", "high") and environment == "production":
        drivers.append(f"{criticality} production asset")
    elif criticality in ("critical", "high"):
        drivers.append(f"{criticality} asset")
    elif environment == "production":
        drivers.append("production asset")

    # Exploitability - the strongest known evidence wins; unknown never counts as "none"
    # an unknown value is only reported where it matters: a KEV listing already gives the maximum
    if kev == UNKNOWN:
        unknown.append("kev")
    if public_exploit == UNKNOWN and kev != "yes":
        unknown.append("public_exploit")
    if kev == "yes":
        exploit, points, known = "known_exploited", EXPLOIT_POINTS["known_exploited"], True
        reason = "Listed in CISA KEV - actively exploited in the wild"
        drivers.append("actively exploited (CISA KEV)")
    elif public_exploit == "yes":
        exploit, points, known = "public_exploit", EXPLOIT_POINTS["public_exploit"], kev == "no"
        reason = "Public exploit / proof of concept available"
        if kev == UNKNOWN:
            reason += " (CISA KEV status unknown)"
        drivers.append("known exploit")
    elif UNKNOWN in (kev, public_exploit):
        exploit, points, known = UNKNOWN, UNKNOWN_EXPLOIT_POINTS, False
        reason = "Exploit status unknown - scored as a public exploit"
    else:
        exploit, points, known = "none", EXPLOIT_POINTS["none"], True
        reason = "Not in CISA KEV, no public exploit known"
    add("exploitability", "Exploitability", exploit, points * 10, max(EXPLOIT_POINTS.values()),
        known, reason)

    total_tenths = sum(t for _, t in factors)
    score = min(100, (total_tenths + 5) // 10)                 # round half up
    why = " + ".join(drivers) if drivers else "No high-severity risk driver"
    if unknown:
        why += "; unknown: " + ", ".join(_LABELS[u] for u in unknown) + " (scored conservatively)"
    return RiskAssessment(score=score, level=level_for(score), factors=tuple(f for f, _ in factors),
                          unknown_factors=tuple(unknown), why=why[0].upper() + why[1:])

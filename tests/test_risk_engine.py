"""Risk Engine (step 1): scoring model, unknown handling, input validation, invariants."""
import itertools
import math
from decimal import Decimal

import pytest

from app.assets.models import Criticality, Environment, InternetFacing
from app.risk import engine
from app.risk.engine import RiskInputError

KNOWN = dict(kev="no", public_exploit="no", reachability="open")


def assess(**kwargs):
    base = dict(cvss=5.0, internet_facing="no", criticality="medium", environment="test", **KNOWN)
    return engine.assess(**{**base, **kwargs})


def factor(result, key):
    return next(f for f in result.factors if f.key == key)


def tenths(result):
    return sum(round(f.points * 10) for f in result.factors)


# --- design examples (carried over from the prototype) ----------------------------------------

def test_design_example_scores_94_critical():
    """OpenSSH 8.2 / CVSS 9.8 / port 22 reachable / internet-facing critical production / public exploit."""
    r = engine.assess(cvss=9.8, internet_facing="yes", criticality="critical", environment="production",
                      kev="no", public_exploit="yes", reachability="open", port=22)
    assert (r.score, r.level) == (94, "CRITICAL")
    assert tenths(r) == 942
    assert [f.points for f in r.factors] == [39.2, 20, 15, 10, 10]
    assert r.why == ("Critical CVSS 9.8 + internet exposure (port 22) + critical production asset"
                     " + known exploit")
    assert r.unknown_factors == ()
    assert r.model_version == engine.MODEL_VERSION


def test_same_cve_lower_risk_in_low_context():
    r = assess(cvss=9.8, internet_facing="no", criticality="medium", environment="development",
               public_exploit="yes", port=22)
    assert (r.score, r.level) == (65, "HIGH")


def test_kev_outranks_public_exploit():
    kev = assess(cvss=7.5, kev="yes", public_exploit="yes")
    poc = assess(cvss=7.5, kev="no", public_exploit="yes")
    assert kev.score - poc.score == 5
    assert "CISA KEV" in kev.why and factor(kev, "exploitability").points == 15


# --- level thresholds through assess() ---------------------------------------------------------

@pytest.mark.parametrize("kwargs, score, level", [
    (dict(cvss=10.0, internet_facing="yes", criticality="critical", environment="production"), 85, "CRITICAL"),
    (dict(cvss=9.8, internet_facing="yes", criticality="critical", environment="production"), 84, "HIGH"),
    (dict(cvss=9.8, criticality="medium", environment="development", public_exploit="yes"), 65, "HIGH"),
    (dict(cvss=9.5, criticality="medium", environment="development", public_exploit="yes"), 64, "MEDIUM"),
    (dict(cvss=7.0, criticality="low", environment="test"), 40, "MEDIUM"),
    (dict(cvss=6.7, criticality="low", environment="test"), 39, "LOW"),
])
def test_level_boundaries(kwargs, score, level):
    r = assess(**kwargs)
    assert (r.score, r.level) == (score, level)


def test_level_for():
    assert [engine.level_for(s) for s in (100, 85, 84, 65, 64, 40, 39, 0)] == \
        ["CRITICAL", "CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW", "LOW"]
    for bad in (-1, 101):
        with pytest.raises(RiskInputError):
            engine.level_for(bad)


def test_level_for_rejects_non_integer_scores():
    for bad in (84.5, True, "85", None):
        with pytest.raises(RiskInputError):
            engine.level_for(bad)


def test_cvss_with_one_decimal_place_is_scored_exactly():
    # review finding: 6.8625 used to be rounded twice (27.45 -> 27.5 -> total 40 MEDIUM)
    with pytest.raises(RiskInputError):
        assess(cvss=6.8625, criticality="low", environment="test")
    r = assess(cvss=6.8, criticality="low", environment="test")       # 27.2 + 8 + 2 + 2 + 0 = 39.2
    assert tenths(r) == 392 and (r.score, r.level) == (39, "LOW")
    assert assess(cvss=Decimal("9.8")) == assess(cvss=9.8) == assess(cvss=Decimal("9.80"))
    assert factor(assess(cvss=9), "severity").points == 36
    zero = factor(assess(cvss=-0.0), "severity")
    assert (zero.value, zero.points, zero.reason) == ("0.0", 0, "CVSS base score 0.0")


# --- unknown values are explicit and conservative ------------------------------------------------

def test_unknown_cvss_is_conservative_and_named():
    r = assess(cvss=None)
    f = factor(r, "severity")
    assert (f.value, f.points, f.known) == ("unknown", 28, False)
    assert "unknown" in f.reason and "cvss" in r.unknown_factors and "CVSS score" in r.why
    assert r.score > assess(cvss=5.0).score                         # never the old "assume 5.0"


def test_unknown_internet_exposure_scores_as_internet_facing():
    r = assess(internet_facing="unknown")
    f = factor(r, "exposure")
    assert (f.points, f.known) == (20, False)
    assert "internet_facing" in r.unknown_factors and "internet exposure" in r.why
    assert r.score == assess(internet_facing="yes").score


def test_reachability_only_halves_exposure_when_a_scan_showed_it_closed():
    assert factor(assess(internet_facing="yes", reachability="open"), "exposure").points == 20
    assert factor(assess(internet_facing="yes", reachability="not_open"), "exposure").points == 10
    assert factor(assess(internet_facing="no", reachability="not_open"), "exposure").points == 4
    closed = assess(internet_facing="yes", reachability="not_open")
    assert "internet" not in closed.why.lower()                     # halved exposure is not a risk driver
    unknown = assess(internet_facing="yes", reachability="unknown")
    assert factor(unknown, "exposure").points == 20
    assert "reachability" in unknown.unknown_factors and "not confirmed by a scan" in \
        factor(unknown, "exposure").reason


@pytest.mark.parametrize("kev, public, value, points, known, unknown", [
    ("yes", "yes", "known_exploited", 15, True, ()),
    ("yes", "unknown", "known_exploited", 15, True, ()),        # unknown exploit status cannot matter
    ("no", "yes", "public_exploit", 10, True, ()),
    ("unknown", "yes", "public_exploit", 10, False, ("kev",)),
    ("unknown", "no", "unknown", 10, False, ("kev",)),
    ("no", "unknown", "unknown", 10, False, ("public_exploit",)),
    ("unknown", "unknown", "unknown", 10, False, ("kev", "public_exploit")),
    ("no", "no", "none", 0, True, ()),
])
def test_exploitability_states(kev, public, value, points, known, unknown):
    r = assess(kev=kev, public_exploit=public)
    f = factor(r, "exploitability")
    assert (f.value, f.points, f.known) == (value, points, known)
    assert r.unknown_factors == unknown
    assert ("unknown:" in r.why) == bool(unknown)


def test_defaults_are_unknown_not_safe():
    r = engine.assess(cvss=5.0, internet_facing="no", criticality="low", environment="test")
    assert set(r.unknown_factors) == {"reachability", "kev", "public_exploit"}
    assert factor(r, "exploitability").points == 10


def test_unknown_never_scores_lower_than_the_favourable_known_values():
    """Replacing a known value by 'unknown' never lowers the score, compared with the
    favourable known values (internal, not reachable, no exploit, CVSS <= the assumed 7.0)."""
    for internet, reach, kev, public in itertools.product(("yes", "no"), ("open", "not_open"),
                                                          ("yes", "no"), ("yes", "no")):
        known = assess(internet_facing=internet, reachability=reach, kev=kev, public_exploit=public)
        assert assess(internet_facing="unknown", reachability=reach, kev=kev,
                      public_exploit=public).score >= known.score
        assert assess(internet_facing=internet, reachability="unknown", kev=kev,
                      public_exploit=public).score >= known.score
        if kev == "no":
            assert assess(internet_facing=internet, reachability=reach, kev="unknown",
                          public_exploit=public).score >= known.score
        if public == "no":
            assert assess(internet_facing=internet, reachability=reach, kev=kev,
                          public_exploit="unknown").score >= known.score
    for cvss in (0.0, 3.1, 5.0, 7.0):
        assert assess(cvss=None).score >= assess(cvss=cvss).score


def test_reasons_use_the_scored_value():
    r = assess(criticality="high", environment="production")
    assert factor(r, "criticality").reason == "Asset is classified as high for the business"
    assert factor(r, "environment").reason == "Runs in production"
    assert r.why == "High production asset"


# --- input validation ---------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs", [
    dict(cvss=-0.1), dict(cvss=10.1), dict(cvss=math.nan), dict(cvss=math.inf), dict(cvss="9.8"),
    dict(cvss=True), dict(cvss=10 ** 400), dict(cvss=9.85), dict(cvss=Decimal("NaN")),
    dict(cvss=Decimal("sNaN")), dict(cvss=Decimal("9.85")), dict(cvss=Decimal("Infinity")),
    dict(port=True), dict(port=22.0),
    dict(internet_facing="isolated"), dict(internet_facing=None),
    dict(criticality="???"), dict(criticality="Critical"), dict(environment="prod"),
    dict(kev=True), dict(public_exploit="maybe"), dict(reachability="closed"),
    dict(port=0), dict(port=70000), dict(port="22"),
])
def test_invalid_inputs_raise_a_defined_error(kwargs):
    with pytest.raises(RiskInputError):
        assess(**kwargs)


def test_accepts_the_asset_model_enums():
    a = engine.assess(cvss=9.8, internet_facing=InternetFacing.YES, criticality=Criticality.CRITICAL,
                      environment=Environment.PRODUCTION, kev="no", public_exploit="yes",
                      reachability="open", port=22)
    b = engine.assess(cvss=9.8, internet_facing="yes", criticality="critical", environment="production",
                      kev="no", public_exploit="yes", reachability="open", port=22)
    assert a == b
    assert all(type(f.value) is str for f in a.factors)            # plain str, not the enum member
    for field, enum_cls in (("internet_facing", InternetFacing), ("criticality", Criticality),
                            ("environment", Environment)):
        for member in enum_cls:
            assess(**{field: member})                               # every asset value is defined


# --- invariants over the whole input space -------------------------------------------------------

def test_invariants_for_all_inputs():
    cvss_values = [None] + [x / 10 for x in range(0, 101)]
    seen = 0
    for cvss, internet, crit, env, kev, public, reach in itertools.product(
            cvss_values, engine.TRI_STATE, engine.CRITICALITY_POINTS, engine.ENVIRONMENT_POINTS,
            engine.TRI_STATE, engine.TRI_STATE, engine.REACHABILITY):
        r = engine.assess(cvss=cvss, internet_facing=internet, criticality=crit, environment=env,
                          kev=kev, public_exploit=public, reachability=reach)
        assert 0 <= r.score <= 100
        assert all(0 <= f.points <= f.max_points for f in r.factors)
        assert r.score == (tenths(r) + 5) // 10
        assert r.level == engine.level_for(r.score)
        expected_unknown = [name for name, is_unknown in (
            ("cvss", cvss is None), ("internet_facing", internet == "unknown"),
            ("reachability", reach == "unknown"), ("kev", kev == "unknown"),
            ("public_exploit", public == "unknown" and kev != "yes")) if is_unknown]
        assert list(r.unknown_factors) == expected_unknown
        known = {f.key: f.known for f in r.factors}
        assert known["severity"] == (cvss is not None)
        assert known["exposure"] == (internet != "unknown" and reach != "unknown")
        assert known["exploitability"] == ("kev" not in expected_unknown
                                           and "public_exploit" not in expected_unknown)
        assert known["criticality"] and known["environment"]
        assert ("unknown:" in r.why) == bool(expected_unknown)
        seen += 1
    assert seen == 102 * 3 * 4 * 4 * 3 * 3 * 3


def test_factor_maxima_sum_to_100_and_model_is_exposed():
    r = assess()
    assert sum(f.max_points for f in r.factors) == 100
    m = engine.model()
    assert m["model_version"] == engine.MODEL_VERSION
    assert m["levels"] == {"CRITICAL": 85, "HIGH": 65, "MEDIUM": 40, "LOW": 0}
    assert m["unknown"]["cvss_assumed"] == 7.0
    m["exposure"]["yes"] = 0                                        # a caller cannot change the model
    m["criticality"]["critical"] = 0
    assert engine.model()["exposure"]["yes"] == 20
    assert factor(assess(internet_facing="yes", criticality="critical"), "exposure").points == 20


def test_deterministic():
    kwargs = dict(cvss=None, internet_facing="unknown", criticality="high", environment="staging")
    first = engine.assess(**kwargs)
    assert all(engine.assess(**kwargs) == first for _ in range(20))
    assert first.as_dict() == engine.assess(**kwargs).as_dict()
    assert first.as_dict()["factors"][0]["key"] == "severity"

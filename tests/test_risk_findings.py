"""Step 3: the Risk Engine applied to correlation findings - stored per finding and per asset."""
import pytest
from correlation_data import FakeNvd, add_version_scan, kev_fetch, session
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.assets.models import Asset
from app.audit.service import SYSTEM
from app.correlation import engine, kev
from app.correlation.service import add_software
from app.database import session_scope
from app.monitoring.models import PortResult

IP = "10.0.0.5"


@pytest.fixture
def nvd():
    return FakeNvd()


@pytest.fixture
def lab(make_asset):
    return make_asset(name="metasploitable", ip_address=IP, internet_facing="yes",
                      criticality="critical", environment="production")


def correlate(nvd):
    with session() as s:
        return engine.run_correlation(s, nvd)


def by_cve(client, asset_id, **params):
    items = client.get(f"/assets/{asset_id}/findings", params=params).json()["items"]
    return {f["cve"]["id"]: f for f in items}


def test_never_assessed_is_not_no_risk(client, lab):
    r = client.get(f"/assets/{lab['id']}/risk").json()
    assert (r["assessed"], r["max_score"], r["open_findings"]) == (False, None, 0)


def test_correlation_stores_explainable_risk_per_finding(client, lab, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    f = by_cve(client, lab["id"])["CVE-2011-2523"]
    risk = f["risk"]
    # 9.8 -> 39.2, internet 20, critical 15, production 10, exploit unknown 10 (no KEV refresh yet)
    assert (risk["score"], risk["level"], risk["model_version"]) == (94, "CRITICAL", "1")
    assert risk["inputs"]["kev"] == "unknown" and risk["inputs"]["reachability"] == "open"
    assert set(risk["unknown_factors"]) == {"kev", "public_exploit"}
    assert "Critical CVSS 9.8" in risk["why"] and "unknown" in risk["why"]
    assert sum(fac["max_points"] for fac in risk["factors"]) == 100

    summary = client.get(f"/assets/{lab['id']}/risk").json()
    assert (summary["assessed"], summary["max_score"], summary["max_level"]) == (True, 94, "CRITICAL")
    assert (summary["open_findings"], summary["findings_with_unknowns"]) == (1, 1)


def test_kev_refresh_rescores_without_a_new_correlation(client, lab, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4"), (80, "Apache httpd", "2.4.49")])
    correlate(nvd)
    with session() as s:
        kev.refresh(s, fetch=kev_fetch())
    found = by_cve(client, lab["id"])
    vsftpd, apache = found["CVE-2011-2523"]["risk"], found["CVE-2021-41773"]["risk"]
    assert vsftpd["inputs"]["kev"] == "yes" and vsftpd["score"] == 99           # KEV: 15 points
    assert apache["inputs"]["kev"] == "no" and "kev" not in apache["unknown_factors"]   # catalogue is current
    assert client.get(f"/assets/{lab['id']}/risk").json()["max_score"] == 99


def test_unknown_cvss_is_not_ranked_below_known_medium(client, lab, nvd):
    add_version_scan(IP, [(80, "Apache httpd", "2.4.49"), (22, "OpenSSH", "7.4p1")])
    correlate(nvd)
    items = client.get("/findings").json()["items"]                        # default: contextual risk
    scores = [i["risk"]["score"] for i in items]
    assert scores == sorted(scores, reverse=True)
    ids = [i["cve"]["id"] for i in items]
    unscored, medium = ids.index("CVE-2099-0002"), ids.index("CVE-2018-15473")
    assert unscored < medium                                               # CVSS unknown -> 7.0, not lowest
    assert items[unscored]["risk"]["inputs"]["cvss"] is None
    cvss_order = [i["cve"]["id"] for i in client.get("/findings", params={"sort": "cvss"}).json()["items"]]
    assert cvss_order.index("CVE-2099-0002") == len(cvss_order) - 1       # the old order is still available


def test_unmapped_software_is_reported_on_the_asset(client, lab, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4"), (9999, "SomeCustomDaemon", "1.0")])
    correlate(nvd)
    warnings = client.get(f"/assets/{lab['id']}/risk").json()["correlation_warnings"]
    assert any("SomeCustomDaemon" in w for w in warnings)


def test_status_changes_update_the_asset_risk(client, client_as, lab, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4"), (80, "Apache httpd", "2.4.49")])
    correlate(nvd)
    top = client.get("/findings").json()["items"][0]
    assert top["cve"]["id"] == "CVE-2011-2523"
    r = client_as("analyst").patch(f"/findings/{top['id']}", json={"status": "accepted_risk",
                                                                   "reason": "isolated lab"})
    assert r.status_code == 200
    summary = client.get(f"/assets/{lab['id']}/risk").json()
    assert summary["accepted_findings"] == 1
    assert summary["max_score"] == max(f["risk"]["score"] for f in client.get(
        "/findings", params={"status": "open"}).json()["items"])
    assert summary["max_score"] < top["risk"]["score"]


def test_asset_context_change_rescores_stored_risk(client, lab, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    assert client.patch(f"/assets/{lab['id']}", json={"internet_facing": "no",
                                                      "environment": "test"}).status_code == 200
    risk = by_cve(client, lab["id"])["CVE-2011-2523"]["risk"]
    assert (risk["inputs"]["internet_facing"], risk["score"]) == ("no", 39 + 8 + 15 + 2 + 10)
    assert client.get(f"/assets/{lab['id']}/risk").json()["max_score"] == risk["score"]


def test_unassessed_asset_is_not_marked_assessed_by_an_edit(client, lab):
    client.patch(f"/assets/{lab['id']}", json={"criticality": "low"})
    assert client.get(f"/assets/{lab['id']}/risk").json()["assessed"] is False


def test_reachability_only_from_an_open_port_in_the_evidence_scan(client, lab, nvd):
    scan_id = add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    with session_scope() as db:
        db.execute(update(PortResult).where(PortResult.scan_id == scan_id).values(state="open|filtered"))
    correlate(nvd)
    assert by_cve(client, lab["id"])["CVE-2011-2523"]["risk"]["inputs"]["reachability"] == "unknown"


def test_manual_software_has_unknown_reachability(client, make_asset, nvd):
    asset = make_asset(name="manual-only", internet_facing="no")
    with session() as s:
        add_software(s, SYSTEM, s.get(Asset, asset["id"]), "vsftpd", "2.3.4", None)
    correlate(nvd)
    risk = by_cve(client, asset["id"])["CVE-2011-2523"]["risk"]
    assert risk["inputs"]["reachability"] == "unknown" and "reachability" in risk["unknown_factors"]


def test_summary_follows_auto_close_and_reopen(client, lab, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    add_version_scan(IP, [(21, "vsftpd", "3.0.5")])                        # fixed version, fresh data
    correlate(nvd)
    closed = client.get(f"/assets/{lab['id']}/risk").json()
    assert (closed["assessed"], closed["open_findings"], closed["max_score"]) == (True, 0, None)
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])                        # regression
    correlate(nvd)
    assert client.get(f"/assets/{lab['id']}/risk").json()["max_score"] == 94


def test_scoring_failure_does_not_break_correlation(client, make_asset, nvd, monkeypatch):
    from app.risk import service as risk
    a = make_asset(name="a-host", ip_address="10.0.0.1")
    b = make_asset(name="b-host", ip_address="10.0.0.2")
    add_version_scan("10.0.0.1", [(21, "vsftpd", "2.3.4")])
    add_version_scan("10.0.0.2", [(21, "vsftpd", "2.3.4")])
    real = risk.score_asset

    def flaky(session, asset, **kwargs):
        if asset.name == "a-host":
            raise RuntimeError("boom")
        return real(session, asset, **kwargs)
    monkeypatch.setattr(risk, "score_asset", flaky)
    run = correlate(nvd)
    assert run.status == "partial" and "risk scoring failed" in run.warnings
    assert by_cve(client, a["id"])["CVE-2011-2523"]["risk"] is None          # finding kept, not scored
    assert by_cve(client, b["id"])["CVE-2011-2523"]["risk"]["score"] > 0     # other assets unaffected


def test_rescoring_failure_keeps_the_kev_catalogue(client, lab, nvd, monkeypatch):
    from app.correlation.models import Cve
    from app.risk import service as risk
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)

    def broken(session):
        raise RuntimeError("boom")
    monkeypatch.setattr(risk, "rescore_all", broken)
    with session() as s:
        assert kev.refresh(s, fetch=kev_fetch()) == 1
    with session() as s:
        assert s.get(Cve, "CVE-2011-2523").known_exploited is True


def test_inactive_assets_keep_their_last_assessment(client, lab, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    client.post(f"/assets/{lab['id']}/deactivate")
    before = by_cve(client, lab["id"])["CVE-2011-2523"]["risk"]
    with session() as s:
        kev.refresh(s, fetch=kev_fetch())                                    # rescore_all skips it
    after = by_cve(client, lab["id"])["CVE-2011-2523"]["risk"]
    assert after == before
    assert client.get(f"/assets/{lab['id']}/risk").json()["asset_status"] == "inactive"


def test_risk_order_is_stable_across_pages(client, lab, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4"), (80, "Apache httpd", "2.4.49"), (22, "OpenSSH", "7.4p1")])
    correlate(nvd)
    full = [i["id"] for i in client.get("/findings").json()["items"]]
    paged = [client.get("/findings", params={"limit": 1, "offset": n}).json()["items"][0]["id"]
             for n in range(len(full))]
    assert paged == full and len(set(full)) == len(full)


def test_permissions_and_not_found(app, client, client_as, lab):
    viewer = client_as("viewer")
    assert viewer.get(f"/assets/{lab['id']}/risk").status_code == 200
    assert viewer.get("/risk/model").json()["levels"]["CRITICAL"] == 85
    anonymous = TestClient(app)
    assert anonymous.get(f"/assets/{lab['id']}/risk").status_code == 401
    assert anonymous.get("/risk/model").status_code == 401
    assert client.get("/assets/not-a-uuid/risk").status_code == 404
    assert client.get("/assets/00000000-0000-0000-0000-000000000000/risk").status_code == 404
    assert client.get("/findings", params={"sort": "bogus"}).status_code == 422

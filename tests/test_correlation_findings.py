"""S5.4: findings lifecycle - new, unchanged, fixed, regression, accepted, NVD outage."""
from datetime import UTC, datetime, timedelta

import pytest
from correlation_data import FakeNvd, add_version_scan, cpe_match, kev_fetch, nvd_cve, session
from sqlalchemy import select

from app.assets.models import Asset
from app.audit.service import SYSTEM
from app.correlation import engine, kev
from app.correlation.models import Cve, Finding, FindingStatus, SoftwareSource
from app.correlation.service import add_software

IP = "10.0.0.5"


@pytest.fixture
def nvd():
    return FakeNvd()


@pytest.fixture
def asset(make_asset):
    return make_asset(name="metasploitable", ip_address=IP)


def correlate(nvd, **kwargs):
    with session() as s:
        return engine.run_correlation(s, nvd, **kwargs)


def findings(asset_id) -> dict[str, Finding]:
    with session() as s:
        return {f.cve_id: f for f in s.scalars(select(Finding).where(Finding.asset_id == asset_id)).unique()}


def test_vsftpd_backdoor_becomes_an_open_finding(asset, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    run = correlate(nvd)

    f = findings(asset["id"])["CVE-2011-2523"]
    assert (f.status, f.port, f.software, f.source, f.confidence) == (
        FindingStatus.OPEN, 21, "vsftpd", SoftwareSource.SCAN, "high")
    assert (f.cve.cvss_score, f.cve.severity) == (9.8, "CRITICAL")
    assert (run.status, run.assets_processed, run.findings_opened) == ("success", 1, 1)


def test_ranges_non_vulnerable_entries_and_platform_configs(asset, nvd):
    add_version_scan(IP, [(22, "OpenSSH", "7.4p1 Debian 10+deb9u7")])
    correlate(nvd)
    found = findings(asset["id"])
    # <= 7.7 matches, 8.5-9.8 does not, vulnerable=false ignored, AND config flagged low confidence
    assert set(found) == {"CVE-2018-15473", "CVE-2099-0004"}
    assert found["CVE-2099-0004"].confidence == "low"
    assert found["CVE-2018-15473"].version == "7.4p1 Debian 10+deb9u7"      # distro suffix kept for display


def test_exact_version_and_unscored_cve(asset, nvd):
    add_version_scan(IP, [(80, "Apache httpd", "2.4.49")])
    correlate(nvd)
    found = findings(asset["id"])
    assert set(found) == {"CVE-2021-41773", "CVE-2099-0002"}
    assert found["CVE-2099-0002"].cve.severity == "UNKNOWN"


def test_rescan_is_idempotent(asset, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    first_seen = findings(asset["id"])["CVE-2011-2523"].first_seen
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    run = correlate(nvd)
    found = findings(asset["id"])
    assert len(found) == 1 and run.findings_opened == 0
    assert found["CVE-2011-2523"].first_seen == first_seen


def test_fixed_then_regression_reopens(asset, nvd):
    add_version_scan(IP, [(22, "OpenSSH", "7.4p1")])
    correlate(nvd)

    add_version_scan(IP, [(22, "OpenSSH", "9.8p1")])                    # patched
    run = correlate(nvd)
    f = findings(asset["id"])["CVE-2018-15473"]
    assert run.findings_closed == 2 and f.status == FindingStatus.RESOLVED and f.resolved_at

    add_version_scan(IP, [(22, "OpenSSH", "7.4p1")])                    # rolled back
    run = correlate(nvd)
    f = findings(asset["id"])["CVE-2018-15473"]
    assert run.findings_reopened == 2 and f.status == FindingStatus.OPEN and f.resolved_at is None


def test_fix_with_ticket_is_verified_fixed(asset, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    with session() as s:
        f = s.scalars(select(Finding)).unique().one()
        f.ticket_key, f.status = "ASSET-123", FindingStatus.IN_REMEDIATION
        s.commit()
    add_version_scan(IP, [(21, "vsftpd", "3.0.5")])
    correlate(nvd)
    assert findings(asset["id"])["CVE-2011-2523"].status == FindingStatus.VERIFIED_FIXED


def test_accepted_risk_stays_accepted_while_still_present(asset, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    with session() as s:
        f = s.scalars(select(Finding)).unique().one()
        f.status = FindingStatus.ACCEPTED_RISK
        s.commit()
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    assert findings(asset["id"])["CVE-2011-2523"].status == FindingStatus.ACCEPTED_RISK


def test_no_new_scan_means_no_conclusion(asset, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    correlate(nvd)                                                       # same scan again
    assert findings(asset["id"])["CVE-2011-2523"].status == FindingStatus.OPEN


def test_nvd_outage_uses_stale_cache(asset, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    nvd.failing.add(("vsftpd_project", "vsftpd"))
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    run = correlate(nvd, max_age=timedelta(0))                           # cache expired, NVD down
    assert run.status == "partial" and "using cached CVE data" in run.warnings   # visible, not silent
    assert findings(asset["id"])["CVE-2011-2523"].status == FindingStatus.OPEN


def test_nvd_outage_without_cache_closes_nothing(asset, nvd):
    nvd.failing.add(("openbsd", "openssh"))
    add_version_scan(IP, [(22, "OpenSSH", "7.4p1")])
    run = correlate(nvd)
    assert run.status == "partial" and "openbsd:openssh" in run.warnings
    assert findings(asset["id"]) == {}


def test_cache_avoids_repeated_nvd_calls(asset, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    calls = len(nvd.calls)
    correlate(nvd)
    assert len(nvd.calls) == calls


def test_unmapped_software_is_reported(asset, nvd):
    add_version_scan(IP, [(9999, "Weird Daemon", "1.0"), (21, "vsftpd", "2.3.4")])
    run = correlate(nvd)
    assert run.unmapped_software == "Weird Daemon"
    assert set(findings(asset["id"])) == {"CVE-2011-2523"}


def test_manual_software_removal_keeps_finding_update_closes_it(asset, nvd):
    from app.correlation.service import remove_software
    with session() as s:
        sw = add_software(s, SYSTEM, s.get(Asset, asset["id"]), "OpenSSH", "9.6p1", None)
    correlate(nvd)
    f = findings(asset["id"])["CVE-2024-6387"]
    assert f.source == SoftwareSource.MANUAL and f.port is None

    with session() as s:                          # entry removed: no evidence of a fix -> stays open
        remove_software(s, SYSTEM, s.get(Asset, asset["id"]), sw.id)
    correlate(nvd)
    assert findings(asset["id"])["CVE-2024-6387"].status == FindingStatus.OPEN

    with session() as s:                          # same product, non-affected version -> closed
        add_software(s, SYSTEM, s.get(Asset, asset["id"]), "OpenSSH", "9.8p1", None)
    correlate(nvd)
    assert findings(asset["id"])["CVE-2024-6387"].status == FindingStatus.RESOLVED


# --- review of PR #7: close only on fresh evidence, no version -> no finding -------------------

def test_stale_cve_data_never_closes_findings(asset, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    nvd.failing.add(("vsftpd_project", "vsftpd"))
    add_version_scan(IP, [(21, "vsftpd", "3.0.5")])                     # looks fixed ...
    run = correlate(nvd, max_age=timedelta(0))                           # ... but CVE data is only stale
    assert findings(asset["id"])["CVE-2011-2523"].status == FindingStatus.OPEN
    assert run.findings_closed == 0 and "cached CVE data" in run.warnings

    nvd.failing.clear()                                                  # fresh data again -> may close
    add_version_scan(IP, [(21, "vsftpd", "3.0.5")])
    correlate(nvd, max_age=timedelta(0))
    assert findings(asset["id"])["CVE-2011-2523"].status == FindingStatus.RESOLVED


@pytest.mark.parametrize("next_scan", [
    [],                                          # port no longer answers
    [(21, "ProFTPD", "1.3.5")],                  # another product answers on the port
    [(21, "vsftpd", None)],                      # same product, version not detected
    [(2121, "vsftpd", "3.0.5")],                 # fixed version, but on another port
])
def test_finding_stays_open_without_proof_of_fix(asset, nvd, next_scan):
    nvd.products[("proftpd", "proftpd")] = []
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    add_version_scan(IP, next_scan)
    assert correlate(nvd).findings_closed == 0
    assert findings(asset["id"])["CVE-2011-2523"].status == FindingStatus.OPEN


def test_software_without_version_creates_no_finding(asset, nvd):
    nvd.products[("openbsd", "openssh")] = [
        nvd_cve("CVE-2099-0003", [cpe_match("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")], 5.0, "MEDIUM")]
    add_version_scan(IP, [(22, "OpenSSH", None)])
    run = correlate(nvd)
    assert findings(asset["id"]) == {}
    assert "OpenSSH (port 22): version unknown" in run.warnings


def test_shared_ip_is_ambiguous(make_asset, nvd):
    a = make_asset(name="a", ip_address=IP)
    make_asset(name="b", ip_address=IP)
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    run = correlate(nvd)
    assert "2 active assets" in run.warnings and findings(a["id"]) == {}


def test_inactive_assets_are_skipped(client, asset, nvd):
    client.post(f"/assets/{asset['id']}/deactivate")
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    assert correlate(nvd).assets_processed == 0


def test_kev_flags_findings(asset, nvd):
    add_version_scan(IP, [(21, "vsftpd", "2.3.4")])
    correlate(nvd)
    with session() as s:
        kev.refresh(s, fetch=kev_fetch())
    cve = findings(asset["id"])["CVE-2011-2523"].cve
    assert cve.known_exploited and str(cve.kev_date_added) == "2021-11-03"


def test_incremental_update_only_touches_tracked_products(asset, nvd):
    add_version_scan(IP, [(22, "OpenSSH", "7.4p1")])
    correlate(nvd)
    nvd.modified = [
        nvd_cve("CVE-2018-15473", [cpe_match("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                             versionEndIncluding="7.7")], 6.5, "MEDIUM"),
        nvd_cve("CVE-2099-0009", [cpe_match("cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*")], 9.0, "CRITICAL"),
    ]
    since = datetime.now(UTC) - timedelta(days=1)
    with session() as s:
        assert engine.sync_modified_cves(s, nvd, since=since) == 1
        assert s.get(Cve, "CVE-2018-15473").cvss_score == 6.5
        assert s.get(Cve, "CVE-2099-0009") is None


def test_a_failing_run_is_logged_not_raised(asset, nvd, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(engine, "correlate_asset", boom)
    run = correlate(nvd)
    assert run.status == "failed" and "boom" in run.warnings and run.finished_at

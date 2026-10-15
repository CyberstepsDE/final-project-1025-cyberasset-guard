"""Findings search (GET /findings?q=): part of the CVE id, the software or the asset name."""
import pytest
from correlation_data import FakeNvd, add_version_scan, session

from app.correlation import engine


@pytest.fixture
def two_assets(make_asset):
    # The same vsftpd 2.3.4 on two assets in different contexts (the demo comparison).
    a = make_asset(name="CM-DEMO-FTP-01", ip_address="10.0.0.5", internet_facing="yes",
                   criticality="critical", environment="production")
    b = make_asset(name="lab_ftp%box", ip_address="10.0.0.6", internet_facing="no",
                   criticality="low", environment="development")
    add_version_scan("10.0.0.5", [(21, "vsftpd", "2.3.4")])
    add_version_scan("10.0.0.6", [(21, "vsftpd", "2.3.4"), (22, "OpenSSH", "7.4p1")])
    with session() as s:
        engine.run_correlation(s, FakeNvd())
    return a, b


def search(client, q, **params):
    r = client.get("/findings", params={"q": q, **params})
    assert r.status_code == 200, r.text
    return sorted((f["asset_name"], f["cve"]["id"], f["risk"]["level"]) for f in r.json()["items"])


def test_search_by_part_of_the_cve_id_shows_the_context_difference(client, two_assets):
    rows = search(client, "2011-2523")
    assert rows == [("CM-DEMO-FTP-01", "CVE-2011-2523", "CRITICAL"), ("lab_ftp%box", "CVE-2011-2523", "MEDIUM")]
    assert search(client, "cve-2011-2523") == rows                     # case-insensitive


def test_search_by_software_and_asset_name(client, two_assets):
    assert {r[1] for r in search(client, "openssh")} and all(r[0] == "lab_ftp%box" for r in search(client, "openssh"))
    assert {r[0] for r in search(client, "demo-ftp")} == {"CM-DEMO-FTP-01"}
    assert {r[0] for r in search(client, "vsftpd")} == {"CM-DEMO-FTP-01", "lab_ftp%box"}


def test_search_wildcards_are_literal(client, two_assets):
    assert {r[0] for r in search(client, "%")} == {"lab_ftp%box"}      # not "match everything"
    assert {r[0] for r in search(client, "_")} == {"lab_ftp%box"}
    assert search(client, "no-such-thing") == []


def test_search_combines_with_other_filters_and_is_bounded(client, two_assets):
    assert search(client, "2011-2523", status="resolved") == []
    assert client.get("/findings", params={"q": "x" * 101}).status_code == 422


def test_search_needs_findings_read(anon_client):
    assert anon_client.get("/findings", params={"q": "cve"}).status_code == 401

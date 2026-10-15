"""Recorded-style NVD API 2.0 data (trimmed real CVEs) and helpers for the correlation tests."""
from __future__ import annotations

import json
from datetime import UTC, datetime

from app import database
from app.correlation.nvd import NvdError
from app.monitoring.models import HostResult, PortResult, Scan


def cpe_match(criteria: str, vulnerable: bool = True, **bounds) -> dict:
    return {"vulnerable": vulnerable, "criteria": criteria, "matchCriteriaId": "00000000", **bounds}


def nvd_cve(cve_id: str, matches: list[dict], score=None, severity=None, version="3.1",
            configurations: list[dict] | None = None) -> dict:
    metrics = {}
    if score is not None:
        key = {"4.0": "cvssMetricV40", "3.1": "cvssMetricV31", "3.0": "cvssMetricV30"}[version]
        metrics[key] = [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
            "version": version, "vectorString": f"CVSS:{version}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "baseScore": score, "baseSeverity": severity}}]
    return {
        "id": cve_id, "published": "2020-01-01T00:00:00.000", "lastModified": "2024-01-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": f"Description of {cve_id}"}],
        "metrics": metrics,
        "configurations": configurations or [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}]}],
    }


VSFTPD_BACKDOOR = nvd_cve("CVE-2011-2523", [cpe_match("cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*")],
                          9.8, "CRITICAL")
OPENSSH_USER_ENUM = nvd_cve("CVE-2018-15473", [cpe_match("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                                         versionEndIncluding="7.7")], 5.3, "MEDIUM", version="3.0")
OPENSSH_REGRESSHION = nvd_cve("CVE-2024-6387", [cpe_match("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                                          versionStartIncluding="8.5", versionEndExcluding="9.8")],
                              8.1, "HIGH")
# "vulnerable": false entries must be ignored.
OPENSSH_NOT_VULNERABLE = nvd_cve("CVE-2099-0001", [cpe_match("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                                             vulnerable=False)], 7.5, "HIGH")
# AND configuration: OpenSSH up to 9.0 only when running on a specific platform.
OPENSSH_ON_PLATFORM = nvd_cve("CVE-2099-0004", [], 6.5, "MEDIUM", configurations=[{"operator": "AND", "nodes": [
    {"operator": "OR", "cpeMatch": [cpe_match("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionEndExcluding="9.0")]},
    {"operator": "OR", "cpeMatch": [cpe_match("cpe:2.3:o:example:router_os:-:*:*:*:*:*:*:*", vulnerable=False)]},
]}])
APACHE_PATH_TRAVERSAL = nvd_cve("CVE-2021-41773", [cpe_match("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")],
                                7.5, "HIGH")
APACHE_NO_SCORE = nvd_cve("CVE-2099-0002", [cpe_match("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                                      versionEndExcluding="2.4.60")])

PRODUCT_CVES = {
    ("vsftpd_project", "vsftpd"): [VSFTPD_BACKDOOR],
    ("openbsd", "openssh"): [OPENSSH_USER_ENUM, OPENSSH_REGRESSHION, OPENSSH_NOT_VULNERABLE, OPENSSH_ON_PLATFORM],
    ("apache", "http_server"): [APACHE_PATH_TRAVERSAL, APACHE_NO_SCORE],
}

KEV_FEED = {"title": "CISA Catalog of Known Exploited Vulnerabilities", "vulnerabilities": [
    {"cveID": "CVE-2011-2523", "vendorProject": "vsftpd", "product": "vsftpd", "dateAdded": "2021-11-03",
     "dueDate": "2022-05-03", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "not-a-cve", "dateAdded": "2021-11-03"},
]}


class FakeNvd:
    """Stands in for NvdClient; serves canned CVEs per vendor/product."""

    def __init__(self, products=None):
        self.products = dict(PRODUCT_CVES if products is None else products)
        self.failing: set[tuple[str, str]] = set()
        self.calls: list[tuple[str, str]] = []
        self.modified: list[dict] = []

    def cves_for_product(self, vendor, product):
        self.calls.append((vendor, product))
        if (vendor, product) in self.failing:
            raise NvdError("HTTP 503")
        return iter(self.products.get((vendor, product), []))

    def cves_modified_between(self, start, end):
        return iter(self.modified)


def kev_fetch(feed=KEV_FEED, status=200):
    return lambda url, headers: (status, json.dumps(feed).encode())


def add_version_scan(ip: str, ports: list[tuple[int, str, str | None]], state: str = "up") -> int:
    """Store a completed Monitoring version scan: ports = [(port, product, version), ...]."""
    now = datetime.now(UTC).isoformat()
    with database.session_scope() as db:
        scan = Scan(scan_type="version", target=ip, status="completed", started_at=now, finished_at=now)
        db.add(scan)
        db.flush()
        db.add(HostResult(scan_id=scan.id, ip=ip, state=state))
        db.add_all(PortResult(scan_id=scan.id, ip=ip, port=port, protocol="tcp", state="open",
                              product=product, version=version) for port, product, version in ports)
        scan_id = scan.id
    return scan_id


def session():
    return next(database.get_session())

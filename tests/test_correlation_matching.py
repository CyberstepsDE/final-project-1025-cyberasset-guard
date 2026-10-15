"""S5.1 / S5.2: CPE mapping, version comparison and CVSS selection (pure functions)."""
import pytest

from app.correlation.cpe import identify, parse_cpe, split_version
from app.correlation.cvss import extract_cvss
from app.correlation.versions import compare_versions, in_range


@pytest.mark.parametrize("a, b, expected", [
    ("2.4.49", "2.4.50", -1), ("2.4.9", "2.4.10", -1), ("8.2p1", "9.3p2", -1), ("1.0", "1.0.0", 0),
    ("7.4p1", "7.4", 1), ("7.4p1", "7.4p2", -1), ("1.0.1g", "1.0.1f", 1), ("1.0.1g", "1.0.2", -1),
    ("2.0rc1", "2.0", -1), ("2.0-beta", "2.0-rc1", -1), ("9.8p1", "9.8", 1),
    ("1:1.2", "1.2", 1), ("1.2", "1:1.0", -1), ("2:1.0", "2:1.0", 0),          # Debian epochs
])
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected


def test_version_ranges():
    assert in_range("7.4p1", end_including="7.7") and in_range("7.7", end_including="7.7")
    assert not in_range("7.8", end_including="7.7")
    assert in_range("8.5", start_including="8.5", end_excluding="9.8")
    assert not in_range("9.8", start_including="8.5", end_excluding="9.8")
    assert not in_range("8.5", start_excluding="8.5")


@pytest.mark.parametrize("raw, version, suffix", [
    ("7.4p1 Debian 10+deb9u7", "7.4p1", "Debian 10+deb9u7"),
    ("8.2p1 Ubuntu 4ubuntu0.5", "8.2p1", "Ubuntu 4ubuntu0.5"),
    ("8.0.21-0ubuntu0.20.04.4", "8.0.21", "-0ubuntu0.20.04.4"),
    ("2.4.29", "2.4.29", None),
    ("1.0.1g", "1.0.1g", None),
    ("2.6.X", None, None),
    ("unknown", None, None),
    ("", None, None),
    (None, None, None),
])
def test_distribution_suffix_is_split_off_and_kept(raw, version, suffix):
    assert split_version(raw) == (version, suffix)


@pytest.mark.parametrize("product, version, expected", [
    ("OpenSSH", "8.2p1 Ubuntu 4ubuntu0.5", ("openbsd", "openssh", "8.2p1")),
    ("Apache httpd", "2.4.49", ("apache", "http_server", "2.4.49")),
    ("nginx", "1.18.0", ("f5", "nginx", "1.18.0")),
    ("Microsoft IIS httpd", "10.0", ("microsoft", "internet_information_services", "10.0")),
    ("Exim smtpd", "4.92", ("exim", "exim", "4.92")),
    ("vsftpd", "2.3.4", ("vsftpd_project", "vsftpd", "2.3.4")),
    ("MySQL", "5.0.51a-3ubuntu5", ("oracle", "mysql", "5.0.51a")),
    ("Samba smbd", "3.0.20-Debian", ("samba", "samba", "3.0.20")),
    ("ProFTPD", "1.3.1", ("proftpd", "proftpd", "1.3.1")),
    ("PostgreSQL DB", "8.3.0 - 8.3.7", ("postgresql", "postgresql", "8.3.0")),
])
def test_catalogue_maps_common_products(product, version, expected):
    ident = identify(product, version)[0]
    assert (ident.vendor, ident.product, ident.version, ident.confidence) == (*expected, "high")


def test_unknown_product_is_unmapped_not_guessed():
    assert identify("Weird FTP Server", "1.2") == []
    assert identify(None, None) == []


def test_cpe_hint_maps_unknown_products():
    assert identify("Weird FTP Server", "1.2", "weird:ftpd")[0].cpe == "cpe:2.3:a:weird:ftpd:1.2:*:*:*:*:*:*:*"
    assert identify("x", "1.0", "cpe:/a:openbsd:openssh:7.4p1")[0].key == "openbsd:openssh"
    assert identify("x", "1.0", "not; a cpe") == []
    assert identify("x", "1.0", "cpe:/o:linux:linux_kernel:5.4") == []      # operating systems not matched


def test_missing_version_is_low_confidence():
    ident = identify("OpenSSH", None)[0]
    assert ident.version is None and ident.confidence == "low"


def test_parse_cpe_formats():
    p = parse_cpe("cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*")
    assert (p.vendor, p.product, p.version, p.update) == ("openbsd", "openssh", "7.4", "p1")
    assert parse_cpe(r"cpe:2.3:a:vendor:prod\:uct:*:*:*:*:*:*:*:*").product == "prod:uct"
    escaped = parse_cpe(r"cpe:2.3:a:vendor:foo\\bar:1.0\*:*:*:*:*:*:*:*")
    assert (escaped.product, escaped.version) == ("foo\\bar", "1.0*")      # escaped, not stripped
    assert parse_cpe("cpe:/a:openbsd:openssh:7.4p1").version == "7.4p1"
    assert parse_cpe("garbage") is None


def _metric(score, severity=None, type_="Primary", **extra):
    data = {"baseScore": score, "vectorString": "VEC", **({"baseSeverity": severity} if severity else {})}
    return {"type": type_, "cvssData": data, **extra}


def test_cvss_prefers_newest_version_and_primary_source():
    assert extract_cvss({"metrics": {"cvssMetricV40": [_metric(8.7, "HIGH")],
                                     "cvssMetricV31": [_metric(9.8, "CRITICAL")]}}).version == "4.0"
    assert extract_cvss({"metrics": {"cvssMetricV31": [_metric(5.0, "MEDIUM", "Secondary"),
                                                       _metric(7.5, "HIGH")]}}).score == 7.5


def test_cvss_v2_fallback_and_missing_score():
    info = extract_cvss({"metrics": {"cvssMetricV2": [_metric(6.8, baseSeverity="MEDIUM")]}})
    assert (info.version, info.severity) == ("2.0", "MEDIUM")
    assert extract_cvss({"metrics": {"cvssMetricV31": [_metric(9.1)]}}).severity == "CRITICAL"
    missing = extract_cvss({"metrics": {}})
    assert missing.severity == "UNKNOWN" and missing.score is None          # unknown, not 0

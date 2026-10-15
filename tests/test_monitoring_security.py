"""Monitoring security: nmap argument injection (ASSET-61), scan scope (ASSET-63), limits (ASSET-62)."""
import socket

import pytest

from app import config
from app.database import session_scope
from app.monitoring import scanner, scheduler
from app.monitoring import targets as tp
from app.monitoring.models import Schedule


@pytest.fixture
def nmap_calls(monkeypatch):
    """Replace the nmap subprocess; records argument lists, never runs a real scan."""
    calls = []

    def fake_run(args):
        calls.append(list(args))
        return "<nmaprun></nmaprun>"
    monkeypatch.setattr(scanner, "_run_nmap", fake_run)
    return calls


@pytest.fixture
def fake_dns(monkeypatch):
    table = {"web01.cybermock.local": ["10.10.10.20"], "evil.example": ["8.8.8.8"],
             "mixed.example": ["10.0.0.9", "8.8.4.4"]}

    def getaddrinfo(host, *args, **kwargs):
        if host not in table:
            raise socket.gaierror("not found")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in table[host]]
    monkeypatch.setattr(tp.socket, "getaddrinfo", getaddrinfo)


# --- target syntax (ASSET-61) ------------------------------------------------------------------

@pytest.mark.parametrize("target, expected", [
    ("10.0.0.5", ("10.0.0.5",)),
    ("10.0.0.0/24", ("10.0.0.0/24",)),
    ("10.0.0.7/24", ("10.0.0.0/24",)),                         # normalised network
    ("192.168.1.1-20", ("192.168.1.1-20",)),
    ("192.168.1.1,5,9", ("192.168.1.1,5,9",)),
    ("fd00::1", ("fd00::1",)),
    ("127.0.0.1   10.1.1.1", ("127.0.0.1", "10.1.1.1")),
])
def test_valid_targets(target, expected):
    assert tp.prepare(target).nmap_args == expected


def test_hostnames_are_resolved_and_pinned(fake_dns):
    assert tp.prepare("web01.cybermock.local").nmap_args == ("10.10.10.20",)


@pytest.mark.parametrize("target", [
    "--script=http-shellshock", "-iL /etc/passwd", "10.0.0.1 -oN /tmp/out", "-sS 10.0.0.1",
    "10.0.0.1;id", "$(id)", "`id`", "10.0.0.1|nc", "10.0.0.1/33", "300.1.1.1", "10.0.0.1-300",
    "a" * 1001, " ".join(["10.0.0.1"] * 33), "", "   ", "10.0.0.0/8",            # > 65536 addresses
    "host_with_underscore", "-",
])
def test_unsafe_or_malformed_targets_are_rejected(target):
    with pytest.raises(tp.TargetError):
        tp.prepare(target)


@pytest.mark.parametrize("ports, ok", [
    ("22,80,443", True), ("1-1024", True), ("T:22,U:53", True), (None, True), ("", True),
    ("-", False), ("0", False), ("1-70000", False), ("22,--script", False), ("80 -oN x", False), ("443-80", False),
])
def test_port_specs(ports, ok):
    if ok:
        tp.validate_ports(ports)
    else:
        with pytest.raises(tp.TargetError):
            tp.validate_ports(ports)


def test_scanner_never_calls_nmap_with_unsafe_input(nmap_calls):
    for call in (lambda: scanner.discover("-iL /etc/passwd"),
                 lambda: scanner.port_scan("10.0.0.1", "22 --script=x"),
                 lambda: scanner.version_scan("10.0.0.1 -oN /tmp/x")):
        with pytest.raises(scanner.ScanTargetError):
            call()
    assert nmap_calls == []


def test_safe_scan_passes_only_validated_tokens(nmap_calls):
    scanner.port_scan("10.0.0.1  10.0.1.0/30", "22,443")
    assert nmap_calls == [["-sT", "-p", "22,443", "10.0.0.1", "10.0.1.0/30"]]


# --- scope (ASSET-63) -------------------------------------------------------------------------------

@pytest.mark.parametrize("target", ["8.8.8.8", "1.1.1.0/24", "192.168.0.0/15", "172.15.255.255",
                                    "2001:4860::8888"])
def test_targets_outside_allowed_networks_are_refused(target):
    with pytest.raises(tp.TargetNotAllowed):
        tp.prepare(target)


def test_hostname_scope_uses_every_resolved_address(fake_dns):
    with pytest.raises(tp.TargetNotAllowed):
        tp.prepare("evil.example")
    with pytest.raises(tp.TargetNotAllowed):
        tp.prepare("mixed.example")                              # one private + one public address


def test_allowed_networks_are_configurable(monkeypatch):
    monkeypatch.setattr(config, "SCAN_ALLOWED_NETWORKS", ("198.51.100.0/24",))
    assert tp.prepare("198.51.100.7").nmap_args == ("198.51.100.7",)
    with pytest.raises(tp.TargetNotAllowed):
        tp.prepare("10.0.0.1")
    monkeypatch.setattr(config, "SCAN_ALLOWED_NETWORKS", ("any",))
    assert tp.prepare("8.8.8.8").nmap_args == ("8.8.8.8",)


def test_scanner_refuses_out_of_scope_target(nmap_calls):
    with pytest.raises(scanner.ScanScopeError):
        scanner.discover("8.8.8.8")
    assert nmap_calls == []


# --- API --------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/monitoring/discover", "/monitoring/portscan", "/monitoring/versionscan"])
def test_api_rejects_injection_with_422(client, nmap_calls, path):
    r = client.post(path, json={"target": "10.0.0.1 --script=vuln"})
    assert r.status_code == 422 and "command-line option" in r.json()["detail"]
    assert nmap_calls == []
    assert client.get("/monitoring/scans").json() == []              # no scan row was created


def test_api_rejects_bad_ports_with_422(client, nmap_calls):
    r = client.post("/monitoring/portscan", json={"target": "10.0.0.1", "ports": "-"})
    assert r.status_code == 422 and nmap_calls == []


def test_api_refuses_out_of_scope_with_403_and_audits(client, nmap_calls):
    r = client.post("/monitoring/discover", json={"target": "8.8.8.8"})
    assert r.status_code == 403 and "outside the allowed scan networks" in r.json()["detail"]
    assert nmap_calls == []
    events = client.get("/audit", params={"action": "monitoring.scope_denied"}).json()["items"]
    assert events and events[0]["outcome"] == "denied" and events[0]["details"]["target"] == "8.8.8.8"


def test_api_allows_valid_scan(client, nmap_calls):
    r = client.post("/monitoring/discover", json={"target": "127.0.0.1"})
    assert r.status_code == 200 and nmap_calls == [["-sn", "127.0.0.1"]]


# --- schedules and limits (ASSET-62) ---------------------------------------------------------------

def test_schedule_minimum_interval_and_validation(client, nmap_calls):
    base = {"scan_type": "discovery", "target": "127.0.0.1"}
    r = client.post("/monitoring/schedules", json={**base, "interval_seconds": 1})
    assert r.status_code == 422 and "at least 900" in r.json()["detail"]
    assert client.post("/monitoring/schedules",
                       json={**base, "target": "-iL /etc/passwd", "interval_seconds": 3600}).status_code == 422
    assert client.post("/monitoring/schedules",
                       json={**base, "target": "8.8.8.8", "interval_seconds": 3600}).status_code == 403
    assert client.post("/monitoring/schedules", json={**base, "interval_seconds": 3600}).status_code == 200


def test_cli_schedule_path_is_validated_too():
    with pytest.raises(ValueError):
        scheduler.add_schedule("discovery", "--script=x", 3600)
    with pytest.raises(ValueError):
        scheduler.add_schedule("discovery", "8.8.8.8", 3600)
    with pytest.raises(ValueError):
        scheduler.add_schedule("discovery", "127.0.0.1", 10)


def test_unsafe_legacy_schedules_are_disabled_at_startup(client):
    with session_scope() as session:
        for target, interval in (("-iL /etc/passwd", 3600), ("8.8.8.8", 3600), ("127.0.0.1", 5),
                                 ("127.0.0.1", 3600)):
            session.add(Schedule(scan_type="discovery", target=target, interval_seconds=interval,
                                 enabled=1, created_at="2026-01-01"))
    scheduler.start()
    rows = {(r["target"], r["interval_seconds"]): r for r in scheduler.list_schedules()}
    assert rows[("-iL /etc/passwd", 3600)]["enabled"] == 0
    assert rows[("8.8.8.8", 3600)]["enabled"] == 0
    assert rows[("127.0.0.1", 5)]["enabled"] == 0
    assert rows[("127.0.0.1", 3600)]["enabled"] == 1
    assert "disabled at startup" in rows[("8.8.8.8", 3600)]["last_error"]
    for key in list(rows):
        scheduler.remove_schedule(rows[key]["id"])


@pytest.mark.parametrize("path", ["/monitoring/scans?limit=1000", "/monitoring/changes?limit=0"])
def test_list_limits_are_capped(client, path):
    assert client.get(path).status_code == 422


# --- security review findings (ASSET-82) -------------------------------------------------------

@pytest.mark.parametrize("target", [
    "010.0.0.1",                 # leading zero: could be read as octal (8.0.0.1)
    "172.016.0.1", "192.168.000.001-5",
    "١٠.0.0.1",        # Arabic-Indic digits
    "::1%eth0", "::1%-oN",       # IPv6 zone ids
])
def test_review_f1_f2_ambiguous_targets_are_rejected(target):
    with pytest.raises(tp.TargetError):
        tp.prepare(target)


def test_review_f1_octet_ranges_reach_nmap_canonicalised():
    assert tp.prepare("10.0.0.1,2,3-5").nmap_args == ("10.0.0.1,2,3-5",)
    assert tp.prepare("10.0.0-1.7").nmap_args == ("10.0.0-1.7",)


NONSTANDARD_NUMERIC = ["010.0.0.1", "172.016.0.1", "10", "8", "0x10.0.0.1", "127.1", "0x7f.0.0.1",
                       "2130706433", "0177.0.0.1", "0x7f000001", "0X7F000001", "0x0a000001", "127.1.",
                       "10.1", "10.0.1", "0x7f.0x0.0x0.0x1"]


@pytest.mark.parametrize("target", NONSTANDARD_NUMERIC)
def test_all_numeric_tokens_are_not_treated_as_hostnames(target, monkeypatch):
    """A host name's top-level label is never all-numeric, so an all-numeric or
    non-canonical dotted token is an (ambiguous) IP and must be rejected, never
    handed to the resolver where e.g. '010' could be read as octal."""
    def no_resolver(*args, **kwargs):
        raise AssertionError("the OS resolver must not decide whether a numeric target is valid")
    monkeypatch.setattr(tp.socket, "getaddrinfo", no_resolver)
    with pytest.raises(tp.TargetError) as exc:
        tp.prepare(target)
    assert not isinstance(exc.value, tp.TargetUnresolvable)


@pytest.mark.parametrize("target", ["127.1", "0x7f.0.0.1", "2130706433", "0x7f000001"])
@pytest.mark.parametrize("path", ["/monitoring/discover", "/monitoring/portscan", "/monitoring/versionscan"])
def test_api_rejects_nonstandard_numeric_targets_with_422(client, nmap_calls, path, target):
    r = client.post(path, json={"target": target, "ports": "22"})
    assert r.status_code == 422
    assert nmap_calls == []
    assert client.get("/monitoring/scans").json() == []


def test_hostnames_with_numeric_or_hex_looking_labels_still_resolve(monkeypatch):
    seen = []

    def getaddrinfo(host, *args, **kwargs):
        seen.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", 0))]
    monkeypatch.setattr(tp.socket, "getaddrinfo", getaddrinfo)
    for host in ("web01.cybermock.local", "10.cybermock.local", "0x7f.cybermock.local", "1-2-3.example",
                 "deadbeef", "db01.0xabc.local", "localhost."):
        assert tp.prepare(host).nmap_args == ("10.0.0.9",)
    assert len(seen) == 7


def test_review_f3_ports_ascii_only():
    assert tp.validate_ports("22\n,80") == "22,80"                # whitespace is removed, never passed on
    assert tp.validate_ports("22\n") == "22"
    with pytest.raises(tp.TargetError):
        tp.validate_ports("٢٢")                         # non-ASCII (Arabic-Indic) digits

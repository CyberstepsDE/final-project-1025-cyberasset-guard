"""Functional tests for the Monitoring module (ASSET-80).

Complements tests/test_monitoring_security.py (which covers target validation,
argument-injection, scope and schedule limits). This file covers the module's
behaviour: nmap XML parsing, scanner error handling, change detection (diff),
scan persistence (service) and scheduler mechanics.

No real nmap binary is used: `_run_nmap` is replaced with a fake that returns
canned XML, so the tests are fast and deterministic. Targets stay inside the
default allowed scan networks (loopback / RFC1918) so scope checks pass.
"""
import subprocess

import pytest

from app import database
from app.database import session_scope
from app.monitoring import diff, scanner, scheduler, service
from app.monitoring.models import Schedule

# --- canned nmap XML --------------------------------------------------------

EMPTY_XML = "<nmaprun></nmaprun>"

DISCOVERY_XML = """<nmaprun>
 <host>
  <status state="up" reason="echo-reply"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <hostnames><hostname name="web01.local" type="PTR"/></hostnames>
  <times srtt="12345" rttvar="100" to="200"/>
 </host>
</nmaprun>"""

HOST_UP_NO_NAME_XML = """<nmaprun>
 <host>
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
 </host>
</nmaprun>"""

PORT_XML = """<nmaprun>
 <host>
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh"/></port>
   <port protocol="tcp" portid="23"><state state="closed" reason="reset"/><service name="telnet"/></port>
   <port protocol="tcp" portid="443"><state state="open|filtered"/>
     <service name="https" product="nginx" version="1.25.3" extrainfo="Ubuntu"/></port>
  </ports>
 </host>
</nmaprun>"""


# --- fixtures ---------------------------------------------------------------

@pytest.fixture
def mdb():
    """Create the Monitoring ORM tables in the per-test temporary database."""
    database.init_models()
    return database


@pytest.fixture
def fake_nmap(monkeypatch):
    """Replace scanner._run_nmap with a fake returning holder['xml']; records calls."""
    holder = {"xml": EMPTY_XML, "calls": []}

    def fake(args):
        holder["calls"].append(list(args))
        return holder["xml"]

    monkeypatch.setattr(scanner, "_run_nmap", fake)
    return holder


@pytest.fixture
def reset_scheduler():
    """Isolate the module-global scheduler so tests never share live jobs."""
    scheduler._scheduler = None
    yield scheduler
    s = scheduler._scheduler
    if s is not None and s.running:
        s.shutdown(wait=False)
    scheduler._scheduler = None


# ============================================================================
# scanner — XML parsing
# ============================================================================

def test_parse_discovery_host():
    (h,) = scanner._parse_hosts(DISCOVERY_XML)
    assert (h.ip, h.hostname, h.state, h.reason) == ("10.0.0.5", "web01.local", "up", "echo-reply")
    assert h.latency_s == pytest.approx(0.012345)       # srtt is microseconds
    assert h.ports == []


def test_parse_down_host_without_times_or_name():
    xml = ('<nmaprun><host><status state="down" reason="no-response"/>'
           '<address addr="10.0.0.2" addrtype="ipv4"/></host></nmaprun>')
    (h,) = scanner._parse_hosts(xml)
    assert h.state == "down" and h.hostname is None and h.latency_s is None


def test_parse_prefers_ipv4_address():
    xml = ('<nmaprun><host><status state="up"/>'
           '<address addr="fd00::1" addrtype="ipv6"/>'
           '<address addr="10.0.0.9" addrtype="ipv4"/>'
           '<address addr="00:11:22:33:44:55" addrtype="mac"/></host></nmaprun>')
    (h,) = scanner._parse_hosts(xml)
    assert h.ip == "10.0.0.9"


def test_parse_skips_host_without_address():
    xml = ('<nmaprun><host><status state="up"/></host>'
           '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>')
    hosts = scanner._parse_hosts(xml)
    assert [h.ip for h in hosts] == ["10.0.0.1"]


def test_parse_ports_open_only_with_version_fields():
    (h,) = scanner._parse_hosts(PORT_XML, with_ports=True)
    assert [(p.port, p.protocol, p.state) for p in h.ports] == [
        (22, "tcp", "open"), (443, "tcp", "open|filtered")]      # closed 23 skipped
    ssh, https = h.ports
    assert (ssh.service, ssh.product, ssh.version) == ("ssh", None, None)
    assert (https.service, https.product, https.version, https.extrainfo) == (
        "https", "nginx", "1.25.3", "Ubuntu")


def test_parse_without_with_ports_ignores_ports():
    (h,) = scanner._parse_hosts(PORT_XML)                        # with_ports defaults to False
    assert h.ports == []


def test_parse_malformed_xml_raises():
    with pytest.raises(scanner.ScannerError, match="could not parse"):
        scanner._parse_hosts("<nmaprun><host>")                  # not well-formed


# ============================================================================
# scanner — _run_nmap error handling
# ============================================================================

def test_run_nmap_missing_binary_raises(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda _name: None)
    with pytest.raises(scanner.ScannerError, match="not found on PATH"):
        scanner._run_nmap(["-sn", "10.0.0.1"])


def test_run_nmap_nonzero_exit_raises(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda _name: "/usr/bin/nmap")

    class _Proc:
        returncode, stdout, stderr = 2, "", "bad flag"

    monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **k: _Proc())
    with pytest.raises(scanner.ScannerError, match="exited with code 2: bad flag"):
        scanner._run_nmap(["-sn", "10.0.0.1"])


def test_run_nmap_timeout_raises(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda _name: "/usr/bin/nmap")

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd=["nmap"], timeout=1)

    monkeypatch.setattr(scanner.subprocess, "run", boom)
    with pytest.raises(scanner.ScannerError, match="timed out"):
        scanner._run_nmap(["-sn", "10.0.0.1"])


# ============================================================================
# diff — change detection (pure _diff_states)
# ============================================================================

def _host(state="up", asset_id=None, ports=None):
    return {"state": state, "asset_id": asset_id, "ports": ports or {}}


def _port(service=None, product=None, version=None):
    return {"service": service, "product": product, "version": version}


def test_diff_detects_every_change_type():
    old = {
        "10.0.0.1": _host(ports={(22, "tcp"): _port("ssh", "OpenSSH", "8.9")}),
        "10.0.0.2": _host(),                                     # will disappear -> host_gone
        "10.0.0.3": _host(state="down"),                        # comes up -> host_up
        "10.0.0.5": _host(ports={(80, "tcp"): _port("http")}),  # port closes
        "10.0.0.6": _host(ports={(25, "tcp"): _port("smtp")}),  # service change
    }
    new = {
        "10.0.0.1": _host(ports={(22, "tcp"): _port("ssh", "OpenSSH", "9.6")}),   # version_change
        "10.0.0.3": _host(state="up"),                                            # host_up
        "10.0.0.4": _host(),                                                      # host_new
        "10.0.0.5": _host(ports={}),                                             # port_closed
        "10.0.0.6": _host(ports={(25, "tcp"): _port("submission")}),             # service_change
    }
    by_type = {(c["ip"], c["change_type"]) for c in diff._diff_states(old, new)}
    assert by_type == {
        ("10.0.0.1", "version_change"), ("10.0.0.2", "host_gone"),
        ("10.0.0.3", "host_up"), ("10.0.0.4", "host_new"),
        ("10.0.0.5", "port_closed"), ("10.0.0.6", "service_change"),
    }


def test_diff_reports_port_open_detail():
    old = {"10.0.0.1": _host(ports={})}
    new = {"10.0.0.1": _host(ports={(443, "tcp"): _port("https")})}
    (change,) = diff._diff_states(old, new)
    assert change["change_type"] == "port_open" and change["port"] == 443
    assert "https" in change["detail"]


def test_diff_ignores_down_host_ports():
    old = {"10.0.0.1": _host(state="down", ports={})}
    new = {"10.0.0.1": _host(state="down", ports={(22, "tcp"): _port("ssh")})}
    assert diff._diff_states(old, new) == []                     # no reachable host, no port diff


def test_diff_no_changes_when_identical():
    state = {"10.0.0.1": _host(ports={(22, "tcp"): _port("ssh", "OpenSSH", "9.6")})}
    assert diff._diff_states(dict(state), dict(state)) == []


# ============================================================================
# service — persistence + auto change detection
# ============================================================================

def test_run_discovery_persists_scan_host_and_asset(mdb, fake_nmap):
    fake_nmap["xml"] = DISCOVERY_XML
    scan_id = service.run_discovery("10.0.0.5")

    scan = service.get_scan(scan_id)
    assert scan["status"] == "completed" and scan["scan_type"] == "discovery"
    assert [h["ip"] for h in scan["hosts"]] == ["10.0.0.5"]
    assert scan["hosts"][0]["state"] == "up" and scan["hosts"][0]["ports"] == []
    assert scan["changes"] == []                                 # first scan, nothing to diff

    (asset,) = service.list_assets()
    assert asset["ip"] == "10.0.0.5" and asset["hostname"] == "web01.local"
    assert fake_nmap["calls"] == [["-sn", "10.0.0.5"]]


def test_run_port_scan_persists_ports(mdb, fake_nmap):
    fake_nmap["xml"] = PORT_XML
    scan = service.get_scan(service.run_port_scan("10.0.0.5", "22,443"))
    ports = scan["hosts"][0]["ports"]
    assert {p["port"]: p["service"] for p in ports} == {22: "ssh", 443: "https"}
    assert ["-sT", "-p", "22,443", "10.0.0.5"] in fake_nmap["calls"]


def test_asset_upsert_is_idempotent_and_keeps_hostname(mdb, fake_nmap):
    fake_nmap["xml"] = DISCOVERY_XML
    service.run_discovery("10.0.0.5")                            # learns hostname web01.local
    fake_nmap["xml"] = HOST_UP_NO_NAME_XML
    service.run_discovery("10.0.0.5")                            # same host, no hostname this time

    (asset,) = service.list_assets()                            # still a single asset row
    assert asset["hostname"] == "web01.local"                   # COALESCE keeps the known name


def test_failed_scan_is_recorded_and_raises(mdb, monkeypatch):
    def boom(_args):
        raise scanner.ScannerError("nmap blew up")

    monkeypatch.setattr(scanner, "_run_nmap", boom)
    with pytest.raises(scanner.ScannerError):
        service.run_discovery("10.0.0.5")

    (scan,) = service.list_scans()
    assert scan["status"] == "failed" and "nmap blew up" in scan["error"]


def test_change_detection_runs_after_each_scan(mdb, fake_nmap):
    fake_nmap["xml"] = EMPTY_XML
    service.run_discovery("10.0.0.5")                            # baseline: host absent
    fake_nmap["xml"] = DISCOVERY_XML
    second = service.run_discovery("10.0.0.5")                   # host now up -> host_new

    changes = diff.list_changes(second)
    assert [c["change_type"] for c in changes] == ["host_new"]
    assert changes[0]["ip"] == "10.0.0.5"


def test_change_detection_is_scoped_to_same_target(mdb, fake_nmap):
    fake_nmap["xml"] = DISCOVERY_XML                            # host 10.0.0.5
    service.run_discovery("10.0.0.5")
    other = ('<nmaprun><host><status state="up"/>'
             '<address addr="10.0.0.6" addrtype="ipv4"/></host></nmaprun>')
    fake_nmap["xml"] = other
    second = service.run_discovery("10.0.0.6")                   # different target
    assert diff.list_changes(second) == []                      # no previous scan of 10.0.0.6


def test_get_scan_returns_none_for_unknown_id(mdb):
    assert service.get_scan(999) is None


# ============================================================================
# scheduler — persistence, execution, lifecycle
# ============================================================================

def test_add_schedule_persists_and_is_listed(mdb, reset_scheduler):
    s = scheduler.add_schedule("discovery", "10.0.0.5", 900)
    assert s["scan_type"] == "discovery" and s["interval_seconds"] == 900 and s["enabled"] == 1
    assert [row["id"] for row in scheduler.list_schedules()] == [s["id"]]
    assert scheduler.get_schedule(s["id"])["target"] == "10.0.0.5"


def test_add_schedule_rejects_unknown_scan_type(mdb, reset_scheduler):
    with pytest.raises(ValueError, match="unknown scan_type"):
        scheduler.add_schedule("portscan", "10.0.0.5", 900)     # 'portscan' is not a runner key


def test_run_scheduled_records_success(mdb, reset_scheduler, monkeypatch):
    s = scheduler.add_schedule("discovery", "10.0.0.5", 900)
    monkeypatch.setattr(scheduler.service, "run_discovery", lambda _target: 4242)

    scheduler._run_scheduled(s["id"])

    row = scheduler.get_schedule(s["id"])
    assert row["last_scan_id"] == 4242 and row["last_run_at"] and row["last_error"] is None


def test_run_scheduled_records_failure(mdb, reset_scheduler, monkeypatch):
    s = scheduler.add_schedule("discovery", "10.0.0.5", 900)

    def boom(_target):
        raise RuntimeError("scan exploded")

    monkeypatch.setattr(scheduler.service, "run_discovery", boom)
    scheduler._run_scheduled(s["id"])

    row = scheduler.get_schedule(s["id"])
    assert row["last_scan_id"] is None and "scan exploded" in row["last_error"]


def test_run_scheduled_skips_disabled_schedule(mdb, reset_scheduler, monkeypatch):
    s = scheduler.add_schedule("discovery", "10.0.0.5", 900)
    with session_scope() as session:
        session.get(Schedule, s["id"]).enabled = 0

    called = []
    monkeypatch.setattr(scheduler.service, "run_discovery", lambda t: called.append(t))
    scheduler._run_scheduled(s["id"])
    scheduler._run_scheduled(999999)                            # missing id: must not raise
    assert called == []


def test_remove_schedule(mdb, reset_scheduler):
    s = scheduler.add_schedule("discovery", "10.0.0.5", 900)
    assert scheduler.remove_schedule(s["id"]) is True
    assert scheduler.get_schedule(s["id"]) is None
    assert scheduler.remove_schedule(s["id"]) is False          # already gone


def test_schedule_problem_helper(mdb, reset_scheduler):
    assert scheduler._schedule_problem("10.0.0.5", None, 900) is None
    assert "below" in scheduler._schedule_problem("10.0.0.5", None, 10)
    assert scheduler._schedule_problem("8.8.8.8", None, 900)    # out of scope -> a reason string

"""Nmap wrapper for the Monitoring module.

Design choice: we shell out to the real `nmap` binary and ask for XML output
(`-oX -`), then parse it. This is more robust and auditable than scraping
human-readable output, and avoids a fragile third-party binding.

Part 1 implements discovery (`-sn`, a "ping scan" — host reachability only,
no port scan). Later parts add port/service/version scanning in this module.
"""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..config import NMAP_BIN, SCAN_TIMEOUT
from . import targets as target_policy


class ScannerError(RuntimeError):
    """Raised when nmap is missing, times out, or returns invalid output."""


@dataclass
class PortResult:
    port: int
    protocol: str                # 'tcp' | 'udp'
    state: str                   # 'open' | 'open|filtered'
    service: str | None = None   # service name (Part 2)
    product: str | None = None   # product/software (Part 3)
    version: str | None = None   # version string (Part 3)
    extrainfo: str | None = None # extra version info (Part 3)


@dataclass
class HostResult:
    ip: str
    hostname: str | None = None
    state: str = "down"          # 'up' | 'down'
    reason: str | None = None
    latency_s: float | None = None
    ports: list[PortResult] = field(default_factory=list)


@dataclass
class ScanResult:
    scan_type: str
    target: str
    args: str
    hosts: list[HostResult] = field(default_factory=list)


def _ensure_nmap() -> str:
    """Return the resolved nmap path or raise a clear error."""
    path = shutil.which(NMAP_BIN)
    if not path:
        raise ScannerError(
            f"nmap binary '{NMAP_BIN}' not found on PATH. "
            "Install it (e.g. `brew install nmap`) or set CAG_NMAP_BIN."
        )
    return path


def _run_nmap(args: list[str]) -> str:
    """Execute nmap with the given args and return its XML stdout."""
    nmap = _ensure_nmap()
    cmd = [nmap, *args, "-oX", "-"]
    try:
        proc = subprocess.run(  # noqa: S603  # cmd is validated targets (app/monitoring/targets.py) + a resolved nmap path
            cmd,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"nmap timed out after {SCAN_TIMEOUT}s") from exc

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "unknown error"
        raise ScannerError(f"nmap exited with code {proc.returncode}: {detail}")
    return proc.stdout


def _parse_ports(host_el) -> list[PortResult]:
    """Parse the open/filtered ports of a <host> element.

    Captures the service name (Part 2) plus product/version/extrainfo, which
    are only populated when version detection (`-sV`, Part 3) is requested.
    Closed ports are skipped — only reachable services are of interest.
    """
    ports: list[PortResult] = []
    for port_el in host_el.findall("ports/port"):
        state_el = port_el.find("state")
        state = state_el.get("state") if state_el is not None else ""
        if not state.startswith("open"):
            continue

        svc = port_el.find("service")
        ports.append(
            PortResult(
                port=int(port_el.get("portid")),
                protocol=port_el.get("protocol", "tcp"),
                state=state,
                service=svc.get("name") if svc is not None else None,
                product=svc.get("product") if svc is not None else None,
                version=svc.get("version") if svc is not None else None,
                extrainfo=svc.get("extrainfo") if svc is not None else None,
            )
        )
    return ports


def _parse_hosts(xml_text: str, with_ports: bool = False) -> list[HostResult]:
    """Parse the <host> elements from nmap XML into HostResult objects."""
    try:
        root = ET.fromstring(xml_text)  # noqa: S314  # XML is nmap's own output from our subprocess, not untrusted network input
    except ET.ParseError as exc:
        raise ScannerError(f"could not parse nmap XML output: {exc}") from exc

    results: list[HostResult] = []
    for host in root.findall("host"):
        # Prefer the IPv4 address; fall back to the first address of any type.
        # (Must test `is None`: an Element with no children is falsy, so an
        # `or` fallback would wrongly discard a matched IPv4 address.)
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        hostname = None
        hn_el = host.find("hostnames/hostname")
        if hn_el is not None:
            hostname = hn_el.get("name")

        status_el = host.find("status")
        state = status_el.get("state", "down") if status_el is not None else "down"
        reason = status_el.get("reason") if status_el is not None else None

        latency_s = None
        times_el = host.find("times")
        if times_el is not None and times_el.get("srtt"):
            # nmap reports srtt in microseconds.
            latency_s = round(int(times_el.get("srtt")) / 1_000_000, 6)

        results.append(
            HostResult(
                ip=ip, hostname=hostname, state=state,
                reason=reason, latency_s=latency_s,
                ports=_parse_ports(host) if with_ports else [],
            )
        )
    return results


class ScanTargetError(ScannerError):
    """Malformed or unsafe target / port specification (never reaches nmap)."""


class ScanScopeError(ScannerError):
    """Target outside CAG_SCAN_ALLOWED_NETWORKS (never reaches nmap)."""


def _safe_targets(target: str) -> list[str]:
    """Validate and scope-check the target; returns the tokens passed to nmap.

    Defence in depth: the API validates first, but scheduled scans and the CLI
    also come through here, so nothing unvalidated is ever handed to nmap.
    """
    try:
        return list(target_policy.prepare(target).nmap_args)
    except target_policy.TargetNotAllowed as exc:
        raise ScanScopeError(str(exc)) from None
    except target_policy.TargetError as exc:
        raise ScanTargetError(str(exc)) from None


def _safe_ports(ports: str | None) -> str | None:
    try:
        return target_policy.validate_ports(ports)
    except target_policy.TargetError as exc:
        raise ScanTargetError(str(exc)) from None


def discover(target: str) -> ScanResult:
    """Part 1 — discovery / reachability.

    Runs an nmap ping scan (`-sn`) against `target` and returns which hosts
    are up. `target` accepts any nmap target syntax:
      - single host:        127.0.0.1  /  scanme.nmap.org
      - CIDR block:          192.168.1.0/24
      - hyphen range:        192.168.1.1-20
      - octet list:          192.168.1.1,2,3
      - several of the above separated by spaces

    Note: by default nmap only reports hosts that are *up*. A target absent
    from the results is unreachable; Part 5 (change detection) uses this.
    """
    targets = _safe_targets(target)
    args = ["-sn", *targets]
    xml_text = _run_nmap(args)
    hosts = _parse_hosts(xml_text)
    return ScanResult(
        scan_type="discovery",
        target=target,
        args="nmap " + " ".join(args),
        hosts=hosts,
    )


def port_scan(target: str, ports: str | None = None) -> ScanResult:
    """Part 2 — open ports & services.

    Runs a TCP connect scan (`-sT`, which needs no root privileges) against
    `target` and returns the open ports with their service names. Service
    names come from nmap's port→service table; actual version detection is
    Part 3 (`-sV`).

    `ports` optionally narrows the scan, e.g. "22,80,443" or "1-1024".
    When omitted, nmap scans its default top-1000 TCP ports.
    """
    targets = _safe_targets(target)
    args = ["-sT"]
    ports = _safe_ports(ports)
    if ports:
        args += ["-p", ports]
    args += targets
    xml_text = _run_nmap(args)
    hosts = _parse_hosts(xml_text, with_ports=True)
    return ScanResult(
        scan_type="port",
        target=target,
        args="nmap " + " ".join(args),
        hosts=hosts,
    )


def version_scan(target: str, ports: str | None = None) -> ScanResult:
    """Part 3 — software / versions.

    Runs version detection (`-sV`) on top of a no-root TCP connect scan
    (`-sT`). For each open port, nmap probes the live service to identify the
    product and version, which populate the product/version/extrainfo fields
    of each PortResult (left null by the Part 2 port scan).

    `ports` optionally narrows the scan, e.g. "22,80,443". Version detection
    sends extra probes, so it is slower than a plain port scan.
    """
    targets = _safe_targets(target)
    args = ["-sT", "-sV"]
    ports = _safe_ports(ports)
    if ports:
        args += ["-p", ports]
    args += targets
    xml_text = _run_nmap(args)
    hosts = _parse_hosts(xml_text, with_ports=True)
    return ScanResult(
        scan_type="version",
        target=target,
        args="nmap " + " ".join(args),
        hosts=hosts,
    )

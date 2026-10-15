"""Scan-target validation and scope enforcement for the Monitoring module.

Every target string is split into tokens; each token must be one of
  * an IPv4 / IPv6 address                          10.0.0.5, fd00::1
  * a CIDR network                                  10.0.0.0/24
  * an nmap IPv4 octet range / list                 10.0.0.1-20, 10.0.1.1,5,9
  * a host name (RFC 1123)                          web01.cybermock.local
Anything else - in particular tokens starting with '-' that nmap would read as
options (--script, -iL, -oN ...) - is rejected (TargetError -> HTTP 422).

Scope: all addresses a token can expand to must lie inside the configured
CAG_SCAN_ALLOWED_NETWORKS (TargetNotAllowed -> HTTP 403). Host names are resolved
once and the resolved addresses are passed to nmap, so a DNS answer cannot
change between the check and the scan (DNS rebinding).
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

from .. import config

MAX_TOKENS = 32
MAX_TARGET_LENGTH = 1000
MAX_ADDRESSES = 65536                  # a /16 at most per scan request
_HOSTNAME_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)", re.IGNORECASE | re.ASCII)
_NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*", re.IGNORECASE | re.ASCII)   # decimal/octal or hex
# ASCII digits only, no leading zeros (nmap/resolvers may read "010" as octal = a different address).
_OCTET_NUM = r"(0|[1-9][0-9]{0,2})"
_OCTET_PART = re.compile(rf"{_OCTET_NUM}(?:-{_OCTET_NUM})?", re.ASCII)
_PORT_ITEM = re.compile(r"(?:[TU]:)?([0-9]{1,5})(?:-([0-9]{1,5}))?", re.ASCII)


class TargetError(ValueError):
    """The target or port specification is malformed or unsafe."""


class TargetUnresolvable(TargetError):
    """A host name could not be resolved (may be transient - not a reason to disable a schedule)."""


class TargetNotAllowed(PermissionError):
    """The target lies (partly) outside the networks this installation may scan."""


@dataclass(frozen=True)
class PreparedTarget:
    nmap_args: tuple[str, ...]        # tokens to append to the nmap command line
    display: str                      # normalised target string for storage / logs


def _allowed_networks():
    if any(n.lower() == "any" for n in config.SCAN_ALLOWED_NETWORKS):
        return None
    try:
        return [ipaddress.ip_network(n, strict=False) for n in config.SCAN_ALLOWED_NETWORKS]
    except ValueError as exc:
        raise TargetError(f"CAG_SCAN_ALLOWED_NETWORKS is invalid: {exc}") from None


def _check_range(first, last, token: str) -> None:
    """Both ends of a contiguous range must lie in the same allowed network."""
    nets = _allowed_networks()
    if nets is None:
        return
    for net in nets:
        if first.version == net.version and first in net and last in net:
            return
    raise TargetNotAllowed(f"target '{token}' is outside the allowed scan networks "
                           f"({', '.join(config.SCAN_ALLOWED_NETWORKS)})")


def _parse_octet_range(token: str):
    """10.0.0.1-20 / 10.0.1.1,5,9 / 10.0.0-3.1 -> (first, last, count, canonical) or None.

    `canonical` is rebuilt from the parsed integers, so nmap only ever sees what was checked.
    """
    octets = token.split(".")
    if len(octets) != 4:
        return None
    lows, highs, canon, count = [], [], [], 1
    for octet in octets:
        values = []
        for part in octet.split(","):
            m = _OCTET_PART.fullmatch(part)
            if not m:
                return None
            lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
            if lo > hi or hi > 255:
                raise TargetError(f"invalid octet range in '{token}'")
            values.append((lo, hi))
        lows.append(min(v[0] for v in values))
        highs.append(max(v[1] for v in values))
        canon.append(",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in values))
        count *= sum(hi - lo + 1 for lo, hi in values)
    first = ipaddress.IPv4Address(".".join(map(str, lows)))
    last = ipaddress.IPv4Address(".".join(map(str, highs)))
    return first, last, count, ".".join(canon)


def _is_hostname(token: str) -> bool:
    host = token.rstrip(".")
    labels = host.split(".")
    # A host name's rightmost (top-level) label is never all-numeric (RFC 3696).
    # An all-numeric token is therefore an IP address, possibly a malformed one
    # such as "010.0.0.1" that a resolver may read as octal (8.0.0.1). Reject it
    # here rather than hand an ambiguous address to getaddrinfo. The same applies to
    # a hex last label ("0x7f000001"), which inet_aton-style resolvers read as an IP.
    if _NUMERIC_LABEL.fullmatch(labels[-1]):
        return False
    return 0 < len(host) <= 253 and all(_HOSTNAME_LABEL.fullmatch(label) for label in labels)


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        raise TargetUnresolvable(f"host name '{host}' cannot be resolved") from None
    return sorted({info[4][0].split("%")[0] for info in infos})


def prepare(target: str) -> PreparedTarget:
    """Validate a target string and return safe nmap arguments (raises TargetError / TargetNotAllowed)."""
    if not isinstance(target, str) or not target.strip():
        raise TargetError("empty scan target")
    if len(target) > MAX_TARGET_LENGTH:
        raise TargetError(f"scan target is longer than {MAX_TARGET_LENGTH} characters")
    tokens = target.split()
    if len(tokens) > MAX_TOKENS:
        raise TargetError(f"at most {MAX_TOKENS} targets per scan")

    args: list[str] = []
    total = 0
    for token in tokens:
        if token.startswith("-"):
            raise TargetError(f"'{token}' is not a valid scan target (looks like a command-line option)")
        if not token.isascii():
            raise TargetError(f"'{token}' contains non-ASCII characters")
        try:                                                    # single address
            addr = ipaddress.ip_address(token)
        except ValueError:
            addr = None
        if addr is not None:
            if getattr(addr, "scope_id", None):
                raise TargetError(f"'{token}': IPv6 zone ids are not supported")
            _check_range(addr, addr, token)
            args.append(str(addr))
            total += 1
            continue
        if "/" in token:                                        # CIDR
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                raise TargetError(f"'{token}' is not a valid network") from None
            _check_range(net.network_address, net.broadcast_address, token)
            args.append(str(net))
            total += net.num_addresses
        elif (rng := _parse_octet_range(token)) is not None:    # nmap octet range / list
            first, last, count, canonical = rng
            _check_range(first, last, token)
            args.append(canonical)
            total += count
        elif _is_hostname(token):                               # host name -> resolved addresses
            addresses = _resolve(token)
            for a in addresses:
                ip = ipaddress.ip_address(a)
                _check_range(ip, ip, f"{token} ({a})")
            args.extend(addresses)
            total += len(addresses)
        else:
            raise TargetError(f"'{token}' is not a valid IP address, network, range or host name")
        if total > MAX_ADDRESSES:
            raise TargetError(f"scan covers more than {MAX_ADDRESSES} addresses - split it up")
    return PreparedTarget(nmap_args=tuple(args), display=" ".join(tokens))


def validate_ports(ports: str | None) -> str | None:
    """'22,80,443' / '1-1024' / 'T:22,U:53' -> normalised spec; anything else raises TargetError."""
    if ports is None or not str(ports).strip():
        return None
    spec = "".join(str(ports).split())                         # drop all whitespace, incl. newlines
    if len(spec) > 200:
        raise TargetError("port specification is too long")
    for item in spec.split(","):
        m = _PORT_ITEM.fullmatch(item)
        if not m:
            raise TargetError(f"invalid port specification '{item}' (use e.g. 22,80,443 or 1-1024)")
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= lo <= hi <= 65535):
            raise TargetError(f"port range '{item}' must lie within 1-65535")
    return spec

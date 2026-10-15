"""S5.1 - map detected or manually entered software to CPE vendor/product/version.

Nmap banners are untrusted input: they are only length-limited and parsed with
anchored regular expressions, never evaluated or passed on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_FIELD_LENGTH = 200

# Nmap product name (lower case) -> NVD (vendor, product) candidates.
# NVD sometimes renames vendors, so a product may have several candidates.
CATALOGUE: dict[str, list[tuple[str, str]]] = {
    "openssh": [("openbsd", "openssh")],
    "dropbear sshd": [("dropbear_ssh_project", "dropbear_ssh")],
    "apache httpd": [("apache", "http_server")],
    "apache tomcat": [("apache", "tomcat")],
    "apache tomcat/coyote jsp engine": [("apache", "tomcat")],
    "nginx": [("f5", "nginx"), ("nginx", "nginx")],
    "lighttpd": [("lighttpd", "lighttpd")],
    "microsoft iis httpd": [("microsoft", "internet_information_services")],
    "jetty": [("eclipse", "jetty")],
    "vsftpd": [("vsftpd_project", "vsftpd"), ("beasts", "vsftpd")],
    "proftpd": [("proftpd", "proftpd")],
    "exim smtpd": [("exim", "exim")],
    "postfix smtpd": [("postfix", "postfix")],
    "isc bind": [("isc", "bind")],
    "mysql": [("oracle", "mysql"), ("mysql", "mysql")],
    "mariadb": [("mariadb", "mariadb")],
    "postgresql db": [("postgresql", "postgresql")],
    "redis key-value store": [("redis", "redis")],
    "mongodb": [("mongodb", "mongodb")],
    "samba smbd": [("samba", "samba")],
    "unrealircd": [("unrealircd", "unrealircd")],
    "php": [("php", "php")],
    "openssl": [("openssl", "openssl")],
}

_SPLIT_23 = re.compile(r"(?<!\\):")
_VERSION = re.compile(r"v?(\d+(?:\.\d+)*[a-z]*\d*)", re.IGNORECASE)
_CPE_NAME = re.compile(r"[a-z0-9_\-.]{1,100}")


@dataclass(frozen=True)
class CpeParts:
    part: str  # a = application, o = operating system, h = hardware
    vendor: str
    product: str
    version: str | None  # None = any ("*")
    update: str | None


@dataclass(frozen=True)
class SoftwareIdentity:
    vendor: str
    product: str
    version: str | None  # normalised, e.g. "7.4p1"
    confidence: str  # high / low (no version known)

    @property
    def key(self) -> str:
        return f"{self.vendor}:{self.product}"

    @property
    def cpe(self) -> str:
        return to_cpe23(CpeParts("a", self.vendor, self.product, self.version, None))


_ESCAPED = re.compile(r"\\(.)")


def _field(value: str) -> str | None:
    """A CPE field: unquoted '*' or '' is a wildcard; a backslash makes the next character literal."""
    if value in ("", "*"):
        return None
    return _ESCAPED.sub(r"\1", value)


def parse_cpe(cpe: str) -> CpeParts | None:
    """Parse a CPE 2.3 formatted string or a CPE 2.2 URI (as printed by Nmap)."""
    cpe = (cpe or "").strip()[:MAX_FIELD_LENGTH * 2]
    if cpe.startswith("cpe:2.3:"):
        fields = _SPLIT_23.split(cpe)[2:]
    elif cpe.startswith("cpe:/"):
        fields = cpe[5:].split(":")
    else:
        return None
    fields += [""] * (5 - len(fields))
    part, vendor, product, version, update = (_field(f) for f in fields[:5])
    if not vendor or not product:
        return None
    return CpeParts((part or "a").lower(), vendor.lower(), product.lower(), version, update)


def to_cpe23(parts: CpeParts) -> str:
    fields = [parts.part, parts.vendor, parts.product, parts.version or "*", parts.update or "*"]
    return "cpe:2.3:" + ":".join(fields) + ":*:*:*:*:*:*"


def split_version(raw: str | None) -> tuple[str | None, str | None]:
    """Split an Nmap version into (comparable version, distribution suffix).

    "7.4p1 Debian 10+deb9u7"   -> ("7.4p1", "Debian 10+deb9u7")
    "8.0.21-0ubuntu0.20.04.4"  -> ("8.0.21", "-0ubuntu0.20.04.4")
    "2.6.X" / "unknown"        -> (None, None)
    """
    raw = (raw or "").strip()[:MAX_FIELD_LENGTH]
    if not raw:
        return None, None
    first = raw.split()[0]
    if re.search(r"\.x\b", first, re.IGNORECASE):
        return None, None
    match = _VERSION.match(first)
    if not match:
        return None, None
    suffix = (first[match.end():] + raw[len(first):]).strip()
    return match.group(1).lower(), suffix or None


def normalize_version(raw: str | None) -> str | None:
    return split_version(raw)[0]


def identify(product: str | None, version: str | None, cpe: str | None = None) -> list[SoftwareIdentity]:
    """CPE identities for one piece of software; [] means 'unmapped' (never guessed).

    `cpe` may be an Nmap/manual CPE string or a plain "vendor:product" pair.
    """
    norm_version = normalize_version(version)
    candidates: list[tuple[str, str, str | None]] = []

    if cpe:
        parts = parse_cpe(cpe)
        if parts is None and cpe.count(":") == 1:
            vendor, prod = (p.strip().lower() for p in cpe.split(":"))
            if _CPE_NAME.fullmatch(vendor) and _CPE_NAME.fullmatch(prod):
                parts = CpeParts("a", vendor, prod, None, None)
        if parts and parts.part == "a":
            candidates.append((parts.vendor, parts.product, norm_version or normalize_version(parts.version)))

    name = (product or "").strip().lower()[:MAX_FIELD_LENGTH]
    for vendor, cpe_product in CATALOGUE.get(name, []):
        candidates.append((vendor, cpe_product, norm_version))

    identities: dict[str, SoftwareIdentity] = {}
    for vendor, cpe_product, ver in candidates:
        ident = SoftwareIdentity(vendor, cpe_product, ver, "high" if ver else "low")
        identities.setdefault(ident.key, ident)
    return list(identities.values())

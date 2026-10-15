"""Central configuration. Override via environment variables (see .env.example).

Values are read once at import time. Invalid values raise ConfigError with a
message that names the variable, so a misconfiguration fails fast at startup
instead of somewhere deep inside a request.
"""
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

MIN_PYTHON = (3, 11)


class ConfigError(RuntimeError):
    """Raised for missing or invalid configuration."""


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _choice_env(name: str, default: str, choices: tuple[str, ...]) -> str:
    value = os.environ.get(name, default).strip().upper() or default
    if value not in choices:
        raise ConfigError(f"{name} must be one of {', '.join(choices)}, got {value!r}")
    return value


def _path_env(name: str, default: Path) -> Path:
    raw = os.environ.get(name, "").strip()
    return Path(raw).expanduser() if raw else default


# SQLite database file (MVP — see Technical Components in the design).
DB_PATH = _path_env("CAG_DB_PATH", BASE_DIR / "cyberasset_guard.db")

# Shared database server instead of the local SQLite file, e.g. the Azure PostgreSQL test database:
#   postgresql+psycopg://<user>:<password>@<server>.postgres.database.azure.com:5432/cyberasset_test?sslmode=require
# Empty = use the SQLite file at CAG_DB_PATH. Keep it in .env (git-ignored), never in code or Git.
DATABASE_URL = os.environ.get("CAG_DATABASE_URL", "").strip() or None
if DATABASE_URL and not DATABASE_URL.startswith(("postgresql://", "postgresql+psycopg://", "sqlite://")):
    raise ConfigError("CAG_DATABASE_URL must start with postgresql+psycopg:// (or postgresql://)")

# Where `python -m app.maintenance backup` writes backups. Keep it outside the
# directory / volume of the live database.
BACKUP_DIR = _path_env("CAG_BACKUP_DIR", BASE_DIR / "backups")

# DEBUG | INFO | WARNING | ERROR
LOG_LEVEL = _choice_env("CAG_LOG_LEVEL", "INFO", ("DEBUG", "INFO", "WARNING", "ERROR"))

def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


# --- Authentication / sessions ---------------------------------------------------
# A session ends after this much inactivity ...
SESSION_IDLE_MINUTES = _int_env("CAG_SESSION_IDLE_MINUTES", 30)
# ... and in any case this long after login.
SESSION_MAX_HOURS = _int_env("CAG_SESSION_MAX_HOURS", 12)
# Send the session cookie only over HTTPS. Turn on whenever the app is served via TLS.
COOKIE_SECURE = _bool_env("CAG_COOKIE_SECURE", False)
# Failed logins before the account is locked, and for how long.
LOGIN_MAX_FAILURES = _int_env("CAG_LOGIN_MAX_FAILURES", 5)
LOGIN_LOCKOUT_MINUTES = _int_env("CAG_LOGIN_LOCKOUT_MINUTES", 15)
# Extra origins allowed to send state-changing requests (comma-separated), e.g. when
# the app is behind a reverse proxy: https://cag.example.com. The app's own origin is always allowed.
TRUSTED_ORIGINS = tuple(o.strip().rstrip("/") for o in os.environ.get("CAG_TRUSTED_ORIGINS", "").split(",")
                        if o.strip())

# --- Monitoring scan policy ------------------------------------------------------
# Networks the application may scan (comma-separated CIDRs). Every scan target - including
# all addresses a host name resolves to - must lie inside one of them. The default allows
# private (RFC 1918 / ULA) and loopback ranges only. "any" disables the check (not recommended).
SCAN_ALLOWED_NETWORKS = tuple(
    n.strip() for n in os.environ.get(
        "CAG_SCAN_ALLOWED_NETWORKS",
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7").split(",") if n.strip())
# Shortest allowed interval for scheduled scans (seconds).
SCAN_MIN_INTERVAL_SECONDS = _int_env("CAG_SCAN_MIN_INTERVAL_SECONDS", 900)
# Maximum scans allowed to run at once (per process); further scan requests get HTTP 429
# and scheduled runs are skipped until a slot frees. Protects the host/DB from overload.
SCAN_MAX_CONCURRENT = _int_env("CAG_SCAN_MAX_CONCURRENT", 2)

# --- Scheduled backups --------------------------------------------------------------
# 0 = no automatic backups (default for local development; the Docker image enables them).
BACKUP_INTERVAL_HOURS = _int_env("CAG_BACKUP_INTERVAL_HOURS", 0, minimum=0)
# Retention applied after each scheduled backup (and by `python -m app.maintenance prune-backups`):
# keep the newest backup of each of the last N days and of each of the last N ISO weeks.
BACKUP_KEEP_DAILY = _int_env("CAG_BACKUP_KEEP_DAILY", 7)
BACKUP_KEEP_WEEKLY = _int_env("CAG_BACKUP_KEEP_WEEKLY", 4, minimum=0)

# --- Vulnerability correlation (NVD / CISA KEV) -----------------------------------------
# Optional NVD API key (https://nvd.nist.gov/developers/request-an-api-key): raises the NVD rate
# limit from 5 to 50 requests per 30 s. Sent only to the NVD API, never logged.
NVD_API_KEY = os.environ.get("CAG_NVD_API_KEY", "").strip() or None
# How long downloaded CVE data per product is reused before asking NVD again.
NVD_CACHE_HOURS = _int_env("CAG_NVD_CACHE_HOURS", 24)
# Refresh KEV + changed CVEs and re-correlate all assets every N hours; 0 = off.
CORRELATION_INTERVAL_HOURS = _int_env("CAG_CORRELATION_INTERVAL_HOURS", 24, minimum=0)
# Correlate the scanned assets automatically after each version scan.
CORRELATION_AFTER_SCAN = _bool_env("CAG_CORRELATION_AFTER_SCAN", True)

# --- Jira Cloud: tasks for qualifying security findings (app/ticketing, see README) ------
# Off by default. When enabled but incomplete, the application still starts; the integration
# reports itself as "misconfigured" (GET /integrations/jira) and creates nothing.
JIRA_ENABLED = _bool_env("CAG_JIRA_ENABLED", False)
# Jira Cloud site, e.g. https://example.atlassian.net (https, *.atlassian.net, no path).
JIRA_BASE_URL = os.environ.get("CAG_JIRA_BASE_URL", "").strip().rstrip("/")
# Key of the EXISTING project the tasks go to (configured, never guessed; no project is created).
JIRA_PROJECT_KEY = os.environ.get("CAG_JIRA_PROJECT_KEY", "").strip().upper()
# Atlassian account e-mail + API token (https://id.atlassian.com/manage-profile/security/api-tokens).
# Keep them in .env (git-ignored); they are sent only to JIRA_BASE_URL and never logged.
JIRA_EMAIL = os.environ.get("CAG_JIRA_EMAIL", "").strip()
JIRA_API_TOKEN = os.environ.get("CAG_JIRA_API_TOKEN", "").strip()
JIRA_ISSUE_TYPE = os.environ.get("CAG_JIRA_ISSUE_TYPE", "").strip() or "Task"
# Label put on every task (mandatory; Jira labels cannot contain spaces).
JIRA_LABEL = os.environ.get("CAG_JIRA_LABEL", "").strip() or "finding"
# Optional Atlassian account id of the default assignee.
JIRA_DEFAULT_ASSIGNEE = os.environ.get("CAG_JIRA_DEFAULT_ASSIGNEE", "").strip() or None
# Incident qualification (Risk Engine levels; no second scoring). AUTO_CREATE=false: manual tasks only.
JIRA_AUTO_CREATE = _bool_env("CAG_JIRA_AUTO_CREATE", True)
JIRA_MIN_SEVERITY = _choice_env("CAG_JIRA_MIN_SEVERITY", "HIGH", ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
# Low-confidence correlations (version unknown / platform-specific CVE) are potential findings that
# require validation: no automatic task unless true (an analyst can still create one by hand).
JIRA_INCLUDE_LOW_CONFIDENCE = _bool_env("CAG_JIRA_INCLUDE_LOW_CONFIDENCE", False)
# Per-request timeout, and retries after the first attempt for temporary errors (backoff 1, 2, 4 ... min).
JIRA_TIMEOUT_SECONDS = _int_env("CAG_JIRA_TIMEOUT_SECONDS", 10)
JIRA_MAX_RETRIES = _int_env("CAG_JIRA_MAX_RETRIES", 3, minimum=0)
# How often the delivery worker runs (it also runs right after each assessment).
JIRA_DELIVERY_INTERVAL_MINUTES = _int_env("CAG_JIRA_DELIVERY_INTERVAL_MINUTES", 5)
# Public URL of this CyberAsset Guard instance, used for links in tasks (optional, https only).
PUBLIC_URL = os.environ.get("CAG_PUBLIC_URL", "").strip().rstrip("/") or None

# Path to the nmap binary (Monitoring module).
NMAP_BIN = os.environ.get("CAG_NMAP_BIN", "nmap")

# Hard ceiling (seconds) for any single nmap invocation.
SCAN_TIMEOUT = _int_env("CAG_SCAN_TIMEOUT", 300)


def validate_runtime(db_path: Path | None = None, check_db_path: bool = True) -> None:
    """Check things that would otherwise fail later with an obscure error."""
    if sys.version_info < MIN_PYTHON:
        raise ConfigError(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required, "
            f"running {sys.version_info.major}.{sys.version_info.minor}")
    if not check_db_path:                               # database server (CAG_DATABASE_URL): no local file
        return
    db_path = Path(db_path) if db_path is not None else DB_PATH
    db_dir = db_path.parent
    if db_path.is_dir():
        raise ConfigError(f"CAG_DB_PATH points to a directory, expected a file: {db_path}")
    try:
        db_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(f"CAG_DB_PATH directory {db_dir} cannot be created: {exc.strerror}") from None
    if not os.access(db_dir, os.W_OK):
        raise ConfigError(f"CAG_DB_PATH directory {db_dir} is not writable")

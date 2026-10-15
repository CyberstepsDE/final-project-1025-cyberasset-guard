"""Minimal client for the Jira Cloud REST API v3 (https://developer.atlassian.com/cloud/jira/platform/rest/v3/).

Like the NVD client it uses only the standard library, talks only to the configured
Jira site (https, *.atlassian.net, redirects never followed so the credentials cannot
be re-sent elsewhere), limits the response size and validates the response shape.

Errors are classified for the delivery worker (`category` is stored on the ticket):
  JiraRetryable  timeout, network, rate_limited (429, Retry-After honoured), server (5xx)
  JiraAmbiguous  the request may have succeeded (create: timeout, 5xx, unreadable answer)
  JiraPermanent  authentication (401), permission (403), invalid_project (project or issue
                 type unknown / not creatable), invalid_request (400 and other 4xx), config
Error messages contain the HTTP status and Jira's own error text, never the credentials.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

DEFAULT_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 1024 * 1024
_PROJECT_KEY = re.compile(r"[A-Z][A-Z0-9_]{1,19}")
_ISSUE_KEY = re.compile(r"[A-Z][A-Z0-9_]{1,19}-\d{1,9}")

# fetch(method, url, headers, body, timeout) -> (http status, response headers, body). A fake in tests.
Fetch = Callable[[str, str, dict, bytes | None, float], tuple[int, dict, bytes]]


class JiraError(RuntimeError):
    retry_after: float | None = None

    def __init__(self, message: str, category: str = "invalid_request"):
        super().__init__(message)
        self.category = category


class JiraRetryable(JiraError):
    def __init__(self, message: str, retry_after: float | None = None, category: str = "server"):
        super().__init__(message, category)
        self.retry_after = retry_after


class JiraAmbiguous(JiraRetryable):
    """The issue may or may not have been created; search by label before trying again."""


class JiraPermanent(JiraError):
    pass


class JiraConfigError(JiraPermanent):
    def __init__(self, message: str):
        super().__init__(message, "config")


@dataclass(frozen=True)
class ProjectMeta:
    issue_type_id: str
    priorities: frozenset[str]
    fields: frozenset[str]


@dataclass(frozen=True)
class JiraSettings:
    base_url: str
    project_key: str
    email: str
    api_token: str
    issue_type: str
    label: str = "finding"
    assignee: str | None = None
    timeout: float = DEFAULT_TIMEOUT_SECONDS

    def __repr__(self) -> str:                       # never print the token (logs, tracebacks)
        return f"JiraSettings(base_url={self.base_url!r}, project_key={self.project_key!r})"


def validate_base_url(url: str) -> str:
    """Only https://<site>.atlassian.net - prevents sending credentials (or requests) anywhere else."""
    parts = urllib.parse.urlsplit(url or "")
    host = (parts.hostname or "").lower()
    if parts.scheme != "https":
        raise JiraConfigError("CAG_JIRA_BASE_URL must use https")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise JiraConfigError("CAG_JIRA_BASE_URL must be the site root, e.g. https://your-site.atlassian.net")
    if parts.port not in (None, 443):
        raise JiraConfigError("CAG_JIRA_BASE_URL must not set a port")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}\.atlassian\.net", host):
        raise JiraConfigError("CAG_JIRA_BASE_URL must be a Jira Cloud site (https://<site>.atlassian.net)")
    return f"https://{host}"


def build_settings(base_url: str, project_key: str, email: str, api_token: str, issue_type: str,
                   assignee: str | None = None, label: str = "finding",
                   timeout: float = DEFAULT_TIMEOUT_SECONDS) -> JiraSettings:
    """Validate the configuration; raises JiraConfigError naming the variable (never its value)."""
    missing = [name for name, value in (("CAG_JIRA_BASE_URL", base_url), ("CAG_JIRA_PROJECT_KEY", project_key),
                                        ("CAG_JIRA_EMAIL", email), ("CAG_JIRA_API_TOKEN", api_token)) if not value]
    if missing:
        raise JiraConfigError(f"missing configuration: {', '.join(missing)}")
    if not _PROJECT_KEY.fullmatch(project_key):
        raise JiraConfigError("CAG_JIRA_PROJECT_KEY must be a Jira project key such as ASSET")
    if "@" not in email:
        raise JiraConfigError("CAG_JIRA_EMAIL must be the e-mail address of the Atlassian account")
    if not issue_type or len(issue_type) > 60:
        raise JiraConfigError("CAG_JIRA_ISSUE_TYPE is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", label):
        raise JiraConfigError("CAG_JIRA_LABEL must be one word (letters, digits, - _ . :)")
    return JiraSettings(validate_base_url(base_url), project_key, email, api_token, issue_type, label,
                        assignee, timeout)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # a 3xx surfaces as HTTPError and is treated as a permanent error


_OPENER = urllib.request.build_opener(_NoRedirect)


def urllib_fetch(method: str, url: str, headers: dict, body: bytes | None,
                 timeout: float = DEFAULT_TIMEOUT_SECONDS) -> tuple[int, dict, bytes]:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("only https URLs are fetched")
    # S310: https is enforced just above; the host is the validated Jira site.
    request = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        try:
            data = exc.read(MAX_RESPONSE_BYTES + 1)
        except OSError:
            data = b""
        return exc.code, dict(exc.headers or {}), data


def _retry_after(headers: dict) -> float | None:
    for key, value in headers.items():
        if key.lower() == "retry-after":
            try:
                return max(0.0, min(float(value), 3600.0))
            except (TypeError, ValueError):
                return None
    return None


def _jira_messages(body: bytes) -> str:
    """Jira's own error text (field validation etc.), shortened; never request data."""
    try:
        data = json.loads(body[:MAX_RESPONSE_BYTES])
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    parts = [str(m) for m in data.get("errorMessages") or [] if isinstance(m, str)]
    errors = data.get("errors")
    if isinstance(errors, dict):
        parts += [f"{k}: {v}" for k, v in errors.items() if isinstance(k, str) and isinstance(v, str)]
    return "; ".join(parts)[:300]


class JiraClient:
    def __init__(self, settings: JiraSettings, fetch: Fetch = urllib_fetch):
        self.settings = settings
        self._fetch = fetch
        token = base64.b64encode(f"{settings.email}:{settings.api_token}".encode()).decode()
        self._headers = {"Authorization": f"Basic {token}", "Accept": "application/json",
                         "User-Agent": "CyberAsset-Guard"}

    def issue_url(self, key: str) -> str:
        return f"{self.settings.base_url}/browse/{key}"

    def _call(self, method: str, path: str, payload: dict | None = None, *, ambiguous: bool = False,
              not_found: str = "invalid_request") -> dict:
        """One request. `ambiguous`: a lost answer may mean the request was carried out (create)."""
        url = self.settings.base_url + path
        headers = dict(self._headers)
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        lost = JiraAmbiguous if ambiguous else JiraRetryable
        where = f"{method} {path.split('?')[0]}"
        try:
            status, resp_headers, data = self._fetch(method, url, headers, body, self.settings.timeout)
        except TimeoutError:
            raise lost(f"{where}: timed out after {self.settings.timeout:g}s", category="timeout") from None
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise lost(f"{where}: connection failed ({type(reason).__name__})", category="network") from None
        if len(data) > MAX_RESPONSE_BYTES:
            raise lost(f"{where}: response larger than {MAX_RESPONSE_BYTES} bytes", category="malformed")
        detail = _jira_messages(data)
        suffix = f" - {detail}" if detail else ""
        if status == 429:
            raise JiraRetryable(f"{where}: HTTP 429 rate limited", _retry_after(resp_headers), "rate_limited")
        if status >= 500:
            raise lost(f"{where}: HTTP {status} Jira server error{suffix}", _retry_after(resp_headers), "server")
        if status == 401:
            raise JiraPermanent(f"{where}: HTTP 401 authentication failed - check CAG_JIRA_EMAIL / "
                                "CAG_JIRA_API_TOKEN", "authentication")
        if status == 403:
            raise JiraPermanent(f"{where}: HTTP 403 the Jira account lacks permission{suffix}", "permission")
        if status == 404:
            raise JiraPermanent(f"{where}: HTTP 404 not found{suffix}", not_found)
        if status >= 300:
            raise JiraPermanent(f"{where}: HTTP {status} request rejected{suffix}", "invalid_request")
        if not data:
            return {}
        try:
            parsed = json.loads(data)
        except ValueError:
            raise lost(f"{where}: response is not JSON", category="malformed") from None
        if not isinstance(parsed, dict):
            raise lost(f"{where}: unexpected response shape", category="malformed")
        return parsed

    def metadata(self) -> ProjectMeta:
        """Validate that the project exists and the issue type can be created there; returns the
        issue type id and the priorities and fields its create screen allows (Jira create metadata)."""
        key = urllib.parse.quote(self.settings.project_key)
        data = self._call("GET", f"/rest/api/3/issue/createmeta/{key}/issuetypes?maxResults=200",
                          not_found="invalid_project")
        types = data.get("issueTypes", data.get("values"))
        if not isinstance(types, list):
            raise JiraRetryable("GET createmeta: unexpected response shape", category="malformed")
        wanted = self.settings.issue_type.lower()
        match = next((t for t in types if isinstance(t, dict) and str(t.get("name", "")).lower() == wanted), None)
        if match is None or not isinstance(match.get("id"), str):
            raise JiraPermanent(f"issue type '{self.settings.issue_type}' is not available in project "
                                f"{self.settings.project_key}", "invalid_project")
        type_id = match["id"]
        data = self._call("GET", f"/rest/api/3/issue/createmeta/{key}/issuetypes/"
                                 f"{urllib.parse.quote(type_id)}?maxResults=200", not_found="invalid_project")
        fields = data.get("fields", data.get("values"))
        if not isinstance(fields, list):
            raise JiraRetryable("GET createmeta fields: unexpected response shape", category="malformed")
        field_ids: set[str] = set()
        priorities: set[str] = set()
        for f in fields:
            if not isinstance(f, dict):
                continue
            fid = f.get("fieldId") or f.get("key")
            if isinstance(fid, str):
                field_ids.add(fid)
            if fid == "priority":
                priorities = {v["name"] for v in f.get("allowedValues") or []
                              if isinstance(v, dict) and isinstance(v.get("name"), str)}
        if "labels" not in field_ids:
            raise JiraPermanent(f"the '{self.settings.issue_type}' create screen of {self.settings.project_key} "
                                "has no Labels field (the mandatory label cannot be set)", "invalid_project")
        return ProjectMeta(type_id, frozenset(priorities), frozenset(field_ids))

    def create_issue(self, fields: dict) -> str:
        """Create an issue; returns its key. JiraAmbiguous if the outcome is unknown."""
        data = self._call("POST", "/rest/api/3/issue", {"fields": fields}, ambiguous=True)
        key = data.get("key")
        if not isinstance(key, str) or not _ISSUE_KEY.fullmatch(key):
            raise JiraAmbiguous("POST /rest/api/3/issue: response has no valid issue key", category="malformed")
        return key

    def find_by_label(self, label: str) -> str | None:
        """Key of the issue in the project carrying `label`, if any (idempotency lookup)."""
        jql = f'project = "{self.settings.project_key}" AND labels = "{label}" ORDER BY created ASC'
        query = urllib.parse.urlencode({"jql": jql, "fields": "status", "maxResults": "1"})
        data = self._call("GET", f"/rest/api/3/search/jql?{query}")
        issues = data.get("issues")
        if not isinstance(issues, list):
            raise JiraRetryable("GET /rest/api/3/search/jql: unexpected response shape", category="malformed")
        if not issues:
            return None
        key = issues[0].get("key") if isinstance(issues[0], dict) else None
        if not isinstance(key, str) or not _ISSUE_KEY.fullmatch(key):
            raise JiraRetryable("GET /rest/api/3/search/jql: issue without a valid key", category="malformed")
        return key

    def add_comment(self, key: str, body: dict) -> None:
        self._call("POST", f"/rest/api/3/issue/{urllib.parse.quote(key)}/comment", {"body": body})

    def get_status(self, key: str) -> str:
        data = self._call("GET", f"/rest/api/3/issue/{urllib.parse.quote(key)}?fields=status")
        status = (data.get("fields") or {}).get("status") if isinstance(data.get("fields"), dict) else None
        name = status.get("name") if isinstance(status, dict) else None
        if not isinstance(name, str):
            raise JiraRetryable("GET issue: response has no status", category="malformed")
        return name[:100]

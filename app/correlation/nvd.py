"""S5.2 - client for the NVD CVE API 2.0 (https://nvd.nist.gov/developers/vulnerabilities).

Uses only the standard library (urllib), talks only to the NVD host, limits the
response size and validates the response shape. The optional API key is sent as
a header and never logged.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from collections.abc import Callable, Iterator
from datetime import datetime

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_PAGES = 25            # 25 x 2000 = 50,000 CVEs per query; far above any single product
TIMEOUT_SECONDS = 60

log = logging.getLogger(__name__)

# fetch(url, headers) -> (http status, body). Replaced by a fake in tests.
Fetch = Callable[[str, dict], tuple[int, bytes]]


class NvdError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a 3xx would otherwise re-send our headers (the API key) elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError with the 3xx status


class _HttpsRedirectOnly(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to https URLs (for header-less public feeds such as CISA KEV)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENERS = {False: urllib.request.build_opener(_NoRedirect),
            True: urllib.request.build_opener(_HttpsRedirectOnly)}


def urllib_fetch(url: str, headers: dict, follow_redirects: bool = False) -> tuple[int, bytes]:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("only https URLs are fetched")
    # S310: the scheme is checked to be https just above, and redirects may only go to https.
    request = urllib.request.Request(url, headers={"User-Agent": "CyberAsset-Guard", **headers})  # noqa: S310
    try:
        with _OPENERS[follow_redirects].open(request, timeout=TIMEOUT_SECONDS) as response:
            return response.status, response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


class NvdClient:
    """Rate-limited NVD client: 5 requests / 30 s without an API key, 50 with one."""

    WINDOW_SECONDS = 30.0
    PAGE_SIZE = 2000
    RETRY_STATUS = {403, 429, 500, 502, 503, 504}  # NVD answers 403 when rate limited

    def __init__(self, api_key: str | None = None, fetch: Fetch = urllib_fetch, max_retries: int = 4,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic):
        self._headers = {"apiKey": api_key} if api_key else {}
        self.max_requests = 50 if api_key else 5
        self._fetch = fetch
        self._max_retries = max_retries
        self._sleep = sleep
        self._clock = clock
        self._sent: deque[float] = deque()

    def _throttle(self) -> None:
        while True:
            now = self._clock()
            while self._sent and now - self._sent[0] >= self.WINDOW_SECONDS:
                self._sent.popleft()
            if len(self._sent) < self.max_requests:
                break
            self._sleep(self.WINDOW_SECONDS - (now - self._sent[0]))
        self._sent.append(self._clock())

    def _get(self, params: dict) -> dict:
        url = f"{NVD_CVE_URL}?{urllib.parse.urlencode(params)}"
        error = ""
        for attempt in range(self._max_retries + 1):
            self._throttle()
            try:
                status, body = self._fetch(url, self._headers)
            except OSError as exc:  # URLError, timeouts, connection resets
                error = type(exc).__name__
            else:
                if status == 200:
                    return self._parse(body)
                if status not in self.RETRY_STATUS:
                    raise NvdError(f"NVD returned HTTP {status}")
                error = f"HTTP {status}"
            if attempt < self._max_retries:
                delay = 6 * 2 ** attempt
                log.warning("NVD request failed (%s), retrying in %ss", error, delay)
                self._sleep(delay)
        raise NvdError(f"NVD request failed after {self._max_retries + 1} attempts: {error}")

    @staticmethod
    def _parse(body: bytes) -> dict:
        if len(body) > MAX_RESPONSE_BYTES:
            raise NvdError("NVD response exceeds the size limit")
        try:
            data = json.loads(body)
        except ValueError:
            raise NvdError("NVD response is not valid JSON") from None
        if (not isinstance(data, dict) or not isinstance(data.get("vulnerabilities", []), list)
                or not isinstance(data.get("totalResults", 0), int)):
            raise NvdError("NVD response has an unexpected format")
        return data

    def search(self, **params) -> Iterator[dict]:
        """Yield the "cve" object of every result, following pagination."""
        start = 0
        for _page in range(MAX_PAGES):
            page = self._get({**params, "startIndex": start, "resultsPerPage": self.PAGE_SIZE})
            vulns = page.get("vulnerabilities") or []
            for item in vulns:
                if isinstance(item, dict) and isinstance(item.get("cve"), dict):
                    yield item["cve"]
            start += len(vulns)
            if not vulns or start >= page.get("totalResults", 0):
                return
        raise NvdError(f"NVD query returned more than {MAX_PAGES} pages; refusing to continue")

    def cves_for_product(self, vendor: str, product: str) -> Iterator[dict]:
        """All CVEs listing any version of vendor:product (versions are evaluated locally)."""
        return self.search(virtualMatchString=f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*")

    def cves_modified_between(self, start: datetime, end: datetime) -> Iterator[dict]:
        """CVEs changed in [start, end] (UTC). NVD allows at most 120 days per request."""
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        return self.search(lastModStartDate=start.strftime(fmt), lastModEndDate=end.strftime(fmt))

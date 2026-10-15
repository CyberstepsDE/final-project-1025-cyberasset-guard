"""S5.2 / S5.3: NVD client (rate limit, retries, validation) and the CISA KEV feed."""
import json
import os

import pytest
from correlation_data import KEV_FEED, kev_fetch

from app.correlation import kev
from app.correlation.nvd import MAX_PAGES, MAX_RESPONSE_BYTES, NvdClient, NvdError, urllib_fetch


def _page(ids, total):
    return json.dumps({"totalResults": total, "vulnerabilities": [{"cve": {"id": i}} for i in ids]}).encode()


def _client(responses, api_key="test-key", **kwargs):
    calls, sleeps = [], []

    def fetch(url, headers):
        calls.append((url, headers))
        response = responses(url) if callable(responses) else next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    return NvdClient(api_key=api_key, fetch=fetch, sleep=sleeps.append, **kwargs), calls, sleeps


def test_paginates_and_sends_api_key_only_as_header():
    def responses(url):
        return 200, _page(["CVE-1", "CVE-2"], 3) if "startIndex=0" in url else _page(["CVE-3"], 3)

    client, calls, _ = _client(responses)
    assert [c["id"] for c in client.cves_for_product("openbsd", "openssh")] == ["CVE-1", "CVE-2", "CVE-3"]
    url, headers = calls[0]
    assert url.startswith("https://services.nvd.nist.gov/rest/json/cves/2.0?")
    assert "virtualMatchString=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh" in url
    assert headers == {"apiKey": "test-key"} and "test-key" not in url


def test_rate_limit_without_and_with_key():
    assert _client(iter([]), api_key=None)[0].max_requests == 5
    assert _client(iter([]))[0].max_requests == 50


def test_throttles_when_the_window_is_full():
    now, sleeps = [0.0], []

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    client = NvdClient(api_key=None, fetch=lambda u, h: (200, _page([], 0)), sleep=sleep, clock=lambda: now[0])
    for _ in range(6):
        list(client.search())
    assert sleeps == [30.0]


def test_retries_on_rate_limit_and_network_errors():
    client, _, sleeps = _client(iter([(403, b""), OSError("reset"), (200, _page(["CVE-1"], 1))]))
    assert [c["id"] for c in client.search()] == ["CVE-1"]
    assert sleeps == [6, 12]


def test_gives_up_after_max_retries_and_does_not_retry_client_errors():
    client, _, sleeps = _client(lambda url: (503, b""), max_retries=2)
    with pytest.raises(NvdError, match="3 attempts"):
        list(client.search())
    client, _, sleeps = _client(lambda url: (404, b""))
    with pytest.raises(NvdError, match="404"):
        list(client.search())
    assert sleeps == []


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"vulnerabilities": "x"}',
                                  b"x" * (MAX_RESPONSE_BYTES + 1)],
                         ids=["not-json", "not-object", "bad-list", "too-large"])
def test_invalid_responses_are_rejected(body):
    client, _, _ = _client(lambda url: (200, body))
    with pytest.raises(NvdError):
        list(client.search())


def test_kev_feed_is_validated():
    assert [i["cveID"] for i in kev.parse_catalogue(json.dumps(KEV_FEED).encode())] == ["CVE-2011-2523"]
    for bad in (b"nope", b"{}", json.dumps({"vulnerabilities": [{"cveID": "x"}]}).encode()):
        with pytest.raises(kev.KevError):
            kev.parse_catalogue(bad)


def test_kev_refresh_caches_and_respects_max_age(client):
    from datetime import timedelta

    from correlation_data import session
    with session() as s:
        assert kev.refresh(s, fetch=kev_fetch()) == 1
        # a failing fetch is not even attempted while the cache is fresh
        assert kev.refresh(s, fetch=kev_fetch(status=500), max_age=timedelta(hours=1)) == 1
        with pytest.raises(kev.KevError, match="HTTP 500"):
            kev.refresh(s, fetch=kev_fetch(status=500))


@pytest.mark.skipif(os.environ.get("CAG_LIVE_NVD") != "1", reason="live NVD test: set CAG_LIVE_NVD=1")
def test_live_nvd_vsftpd_backdoor():
    ids = {c["id"] for c in NvdClient().cves_for_product("vsftpd_project", "vsftpd")}
    assert "CVE-2011-2523" in ids


def test_pagination_is_capped():
    client, calls, _ = _client(lambda url: (200, _page(["CVE-1"], 10 ** 9)))
    with pytest.raises(NvdError, match="pages"):
        list(client.search())
    assert len(calls) == MAX_PAGES


def test_redirects_are_never_followed_with_the_api_key(monkeypatch):
    """A 3xx from NVD must not re-send the apiKey header to the redirect target."""
    import io
    import urllib.request

    from app.correlation import nvd

    sent = []

    class FakeHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            sent.append((req.full_url, req.get_header("Apikey")))
            resp = urllib.request.addinfourl(io.BytesIO(b""), {"Location": "https://evil.example/steal"},
                                             req.full_url, 302)
            resp.msg = "Found"
            return resp

    monkeypatch.setitem(nvd._OPENERS, False, urllib.request.build_opener(FakeHandler, nvd._NoRedirect))
    assert urllib_fetch("https://services.nvd.nist.gov/rest/json/cves/2.0", {"apiKey": "secret"})[0] == 302
    assert sent == [("https://services.nvd.nist.gov/rest/json/cves/2.0", "secret")]   # one request, no follow
    with pytest.raises(ValueError):
        urllib_fetch("http://services.nvd.nist.gov/", {})

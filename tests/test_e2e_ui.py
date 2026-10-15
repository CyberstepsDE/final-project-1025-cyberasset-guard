"""End-to-end browser tests for the web UI (ASSET-83).

Opt-in: set CAG_TEST_E2E=1 and have Playwright's browsers installed
(`python -m playwright install chromium`). The tests run headless against a
throwaway uvicorn server backed by a temporary database, with one user per role.

Covered: login/logout, role-dependent visibility, asset create/edit/deactivate,
validation messages, search, the users and audit pages, absence of console errors
on the main pages, and XSS-escaping of attacker-controlled asset fields.
"""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from conftest import TEST_PASSWORD

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    os.environ.get("CAG_TEST_E2E") != "1",
    reason="set CAG_TEST_E2E=1 (and install Playwright browsers) to run the UI e2e tests")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _env(db_path: Path) -> dict:
    return {**os.environ, "CAG_DB_PATH": str(db_path), "CAG_BACKUP_DIR": str(db_path.parent / "bk"),
            "CAG_CORRELATION_AFTER_SCAN": "false"}


def _create_user(db_path: Path, username: str, role: str) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "app.maintenance", "create-user", username, "--role", role, "--password-stdin"],
        cwd=ROOT, env=_env(db_path), input=TEST_PASSWORD + "\n", capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr


@pytest.fixture(scope="session")
def live_server(tmp_path_factory):
    """A real uvicorn server on a temp database, with an admin, analyst and viewer user."""
    db = tmp_path_factory.mktemp("e2e") / "e2e.db"
    for name, role in (("admin", "admin"), ("analyst", "analyst"), ("viewer", "viewer")):
        _create_user(db, name, role)
    port = _free_port()
    log = (db.parent / "server.log").open("w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, env=_env(db), stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            if proc.poll() is not None:
                raise AssertionError("server exited early; see server.log")
            try:
                if httpx.get(f"{base}/health/ready", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        else:
            raise AssertionError("server did not become ready")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _login(page, base: str, username: str) -> None:
    page.goto(f"{base}/#/assets")
    page.wait_for_selector("#login-form")
    page.fill("#l-username", username)
    page.fill("#l-password", TEST_PASSWORD)
    page.click("#login-form button[type='submit']")
    page.wait_for_selector("input[name='q']")          # the assets list has loaded (all roles)


@pytest.fixture
def errors(page):
    """Collects console errors and uncaught page errors for the current page.
    Ignores the favicon 404 the browser emits for a page with no favicon link."""
    found: list[str] = []

    def on_console(m):
        if m.type == "error" and "favicon" not in m.text.lower():
            found.append(m.text)

    page.on("console", on_console)
    page.on("pageerror", lambda e: found.append(str(e)))
    return found


# --- authentication ---------------------------------------------------------

def test_login_and_logout(page, live_server):
    _login(page, live_server, "admin")
    assert page.is_visible("#mainnav")
    page.click("#logout")
    page.wait_for_selector("#login-form")              # back to the sign-in form
    assert page.is_hidden("#mainnav")


def test_wrong_password_is_rejected(page, live_server):
    page.goto(f"{live_server}/#/assets")
    page.wait_for_selector("#login-form")
    page.fill("#l-username", "admin")
    page.fill("#l-password", "wrong-password")
    page.click("#login-form button[type='submit']")
    page.wait_for_selector("#login-error")
    assert "invalid" in page.text_content("#login-error").lower()


# --- role-dependent visibility ----------------------------------------------

def test_viewer_sees_read_only_ui(page, live_server):
    _login(page, live_server, "viewer")
    assert page.locator('a[href="#/assets/new"]').count() == 0        # no "Add Asset"
    assert page.locator('#mainnav a[href="#/candidates"]').count() == 0
    assert page.locator('#mainnav a[href="#/users"]').count() == 0
    assert page.locator('#mainnav a[href="#/audit"]').count() == 0


def test_analyst_can_write_but_not_administer(page, live_server):
    _login(page, live_server, "analyst")
    assert page.locator('a[href="#/assets/new"]').count() >= 1          # "Add Asset" is available
    assert page.locator('#mainnav a[href="#/candidates"]').count() == 1
    assert page.locator('#mainnav a[href="#/users"]').count() == 0
    assert page.locator('#mainnav a[href="#/audit"]').count() == 0


def test_admin_sees_users_and_audit(page, live_server):
    _login(page, live_server, "admin")
    assert page.locator('#mainnav a[href="#/users"]').count() == 1
    assert page.locator('#mainnav a[href="#/audit"]').count() == 1


# --- asset lifecycle + validation + search ----------------------------------

def _create_asset(page, base, name, **fields):
    page.goto(f"{base}/#/assets/new")
    page.wait_for_selector("#asset-form")
    page.fill("#f-name", name)
    page.select_option("#f-asset_type", fields.get("asset_type", "server"))
    page.select_option("#f-environment", fields.get("environment", "production"))
    page.select_option("#f-criticality", fields.get("criticality", "high"))
    if "ip_address" in fields:
        page.fill("#f-ip_address", fields["ip_address"])
    if "description" in fields:
        page.fill("#f-description", fields["description"])
    page.click("#asset-form button[type='submit']")
    page.wait_for_selector("#toggle-status")           # navigated to the new asset's detail page


def test_asset_create_edit_deactivate(page, live_server):
    _login(page, live_server, "analyst")
    name = f"e2e-crud-{os.getpid()}"
    _create_asset(page, live_server, name, ip_address="10.0.4.21")
    assert name in page.text_content("h1")

    page.click('a[href^="#/assets/"][href$="/edit"]')   # the Edit button on the detail page
    page.wait_for_selector("#asset-form")
    page.fill("#f-owner", "Blue Team")
    page.click("#asset-form button[type='submit']")
    page.wait_for_selector("#toggle-status")           # back on the detail page
    assert "Blue Team" in page.content()

    page.click("#toggle-status")                        # Deactivate -> confirm dialog
    page.wait_for_selector("#confirm-dialog[open]")
    page.click("#confirm-ok")
    page.wait_for_selector(".notice")
    assert "inactive" in page.text_content(".notice").lower()


def test_new_asset_validation_message(page, live_server):
    _login(page, live_server, "analyst")
    page.goto(f"{live_server}/#/assets/new")
    page.wait_for_selector("#asset-form")
    page.click("#asset-form button[type='submit']")    # submit empty -> required-field errors
    page.wait_for_selector("#f-name[aria-invalid='true']")
    assert page.text_content("#e-name").strip() != ""


def test_search_filters_the_asset_list(page, live_server):
    _login(page, live_server, "analyst")
    marker = f"needle{os.getpid()}"
    _create_asset(page, live_server, f"{marker}-asset", ip_address="10.0.4.22")
    page.goto(f"{live_server}/#/assets")
    page.wait_for_selector("input[name='q']")
    page.fill("input[name='q']", marker)
    page.press("input[name='q']", "Enter")             # submit now instead of waiting on the debounce
    page.wait_for_selector(f'#results a:has-text("{marker}-asset")')
    assert page.locator(f'#results a:has-text("{marker}-asset")').count() == 1


# --- admin pages ------------------------------------------------------------

def test_users_page_lists_accounts(page, live_server):
    _login(page, live_server, "admin")
    page.goto(f"{live_server}/#/users")
    page.wait_for_selector("table")                     # the users table has loaded
    content = page.content()
    assert "analyst" in content and "viewer" in content


def test_audit_page_shows_events(page, live_server):
    _login(page, live_server, "admin")
    page.goto(f"{live_server}/#/audit")
    page.wait_for_selector("table.audit")              # sign-in events are already recorded
    assert "auth.login" in page.content()


# --- no console errors + XSS ------------------------------------------------

def test_no_console_errors_on_main_pages(page, live_server, errors):
    _login(page, live_server, "admin")
    _create_asset(page, live_server, f"e2e-clean-{os.getpid()}", ip_address="10.0.4.23")
    detail_url = page.url                               # asset detail incl. the monitoring section
    errors.clear()                                      # ignore the pre-login /auth/me 401 from sign-in
    for route in ("#/dashboard", "#/assets", "#/findings", "#/assessments", "#/candidates", "#/users", "#/audit"):
        page.goto(f"{live_server}/{route}")
        page.wait_for_load_state("networkidle")
    page.goto(detail_url)
    page.wait_for_load_state("networkidle")
    assert errors == [], f"console/page errors: {errors}"


def test_leaving_a_page_while_it_loads_causes_no_errors(page, live_server, errors):
    """Slow API answers (CI runners, Azure DB) arrive after the user has moved on; a page's
    loader must not write into the next page or fail on its missing elements."""
    page.add_init_script(r"""
        const fetch0 = window.fetch;
        window.__delayed = 0;
        window.fetch = (url, opts) => /\/(users|audit)\b/.test(String(url))
            ? (window.__delayed++, new Promise((r) => setTimeout(r, 400)).then(() => fetch0(url, opts)))
            : fetch0(url, opts);
    """)
    _login(page, live_server, "admin")
    errors.clear()
    for route in ("#/users", "#/assets", "#/audit", "#/assets"):
        page.evaluate(f"location.hash = '{route}'")
        page.wait_for_timeout(100)                      # leave before the delayed answer arrives
    page.wait_for_timeout(800)                          # let the late answers land
    assert page.evaluate("window.__delayed") >= 2                    # the slow answers did happen
    assert errors == [], f"console/page errors: {errors}"
    assert page.locator("#users-box, #audit-results").count() == 0   # still on the assets page


def test_asset_fields_are_xss_escaped(page, live_server):
    # An <img onerror> payload executes if a value is injected as raw HTML; esc() must prevent it.
    _login(page, live_server, "analyst")
    payload = '<img src=x onerror="window.__xss=1">'
    _create_asset(page, live_server, f"xss{os.getpid()} {payload}",
                  ip_address="10.0.4.24", description=payload)
    page.wait_for_selector(".breadcrumb")
    page.wait_for_timeout(300)                          # give any (wrongly) injected handler time to fire
    assert page.evaluate("() => window.__xss") in (None, False)
    assert "onerror" in page.content()                 # the payload is present as escaped literal text


# --- Jira column (API answers mocked in the browser; no Jira site involved) ---------------------

def _finding(fid, ticket=None, eligibility=None, **kw):
    risk = {"score": 94, "level": "CRITICAL", "factors": [], "unknown_factors": [], "why": "Critical CVSS",
            "model_version": "1", "assessed_at": "2026-10-14T10:00:00Z"}
    return {"id": fid, "asset_id": "a1", "asset_name": "web-server-01", "software": "vsftpd", "version": "2.3.4",
            "port": 21, "protocol": "tcp", "confidence": "high", "status": "open", "status_reason": None,
            "risk": risk, "cve": {"id": f"CVE-2011-{2520 + fid}", "nvd_url": "https://nvd.nist.gov/",
                                  "known_exploited": False, "cvss_score": 9.8},
            "ticket": ticket, "jira_eligibility": eligibility, **kw}


def test_findings_show_jira_state_link_and_actions(page, live_server, errors):
    jira = {"state": "enabled", "problem": None, "base_url": "https://example.atlassian.net",
            "project_key": "ASSET", "issue_type": "Task", "label": "finding", "max_retries": 3,
            "policy": {"auto_create": True, "min_severity": "HIGH", "levels": ["CRITICAL", "HIGH"],
                       "include_low_confidence": False, "finding_statuses": ["open", "in_remediation"]},
            "tickets": {"created": 1, "error": 1}, "last_error": None}
    base_ticket = {"trigger": "auto", "requested_by": None, "jira_status": None, "attempts": 1,
                   "next_attempt_at": None, "last_attempt_at": None, "synced_at": None,
                   "created_at": "2026-10-14T10:00:00Z", "issue_key": None, "issue_url": None,
                   "last_error": None, "error_category": None}
    payload = '<img src=x onerror="window.__xss=1">'
    items = [
        _finding(1, {**base_ticket, "state": "created", "issue_key": "ASSET-7",
                     "issue_url": "https://example.atlassian.net/browse/ASSET-7", "jira_status": "To Do"}),
        _finding(2, {**base_ticket, "state": "error", "last_error": "HTTP 401 authentication failed",
                     "error_category": "authentication"}),
        _finding(3, None, {"automatic": False, "manual": True, "reason": f"risk level MEDIUM is below HIGH {payload}",
                           "manual_reason": None}),
    ]
    requested, polls = [], []
    created = {**base_ticket, "state": "created", "issue_key": "ASSET-8",
               "issue_url": "https://example.atlassian.net/browse/ASSET-8"}

    def ticket_route(route):
        if route.request.method == "POST":
            requested.append(route.request.url)
            return route.fulfill(status=202, json={"queued": True, "ticket": {**base_ticket, "state": "pending"}})
        polls.append(route.request.url)                 # GET: pending first, then created
        if len(polls) < 2:
            return route.fulfill(json={**base_ticket, "state": "pending"})
        items[1]["ticket"] = created                     # what the next list request returns
        return route.fulfill(json=created)

    page.route("**/integrations/jira", lambda r: r.fulfill(json=jira))
    page.route("**/findings?*", lambda r: r.fulfill(json={"total": 3, "limit": 200, "offset": 0, "items": items}))
    page.route("**/findings/*/ticket", ticket_route)
    _login(page, live_server, "analyst")
    errors.clear()                                      # ignore the pre-login /auth/me 401 from sign-in
    page.goto(f"{live_server}/#/findings")
    page.wait_for_selector(".jira-cell a")
    link = page.locator(".jira-cell a")
    assert link.inner_text() == "ASSET-7" and link.get_attribute("href").startswith("https://example.atlassian.net/")
    assert link.get_attribute("rel") == "noopener noreferrer"
    cells = page.locator(".jira-cell")
    assert "Failed" in cells.nth(1).inner_text() and "Retry" in cells.nth(1).inner_text()
    assert "Not eligible" in cells.nth(2).inner_text() and "Create Jira Task" in cells.nth(2).inner_text()
    assert page.evaluate("() => window.__xss") in (None, False)          # the reason is escaped text
    cells.nth(1).locator("button").click()
    page.wait_for_selector("text=Jira task requested")
    assert requested and requested[0].endswith("/findings/2/ticket")
    # polled every second: the link appears in the row without a manual reload
    page.wait_for_selector(".jira-cell a:has-text('ASSET-8')", timeout=6000)
    page.wait_for_selector("text=Jira task ASSET-8 created")
    assert len(polls) >= 2 and all(u.endswith("/findings/2/ticket") for u in polls)
    row2 = page.locator("tr[data-finding='2']")
    row2.locator("[data-why]").click()                    # the link is also in the finding's details
    detail = page.locator("[data-why-row='2']")
    assert detail.locator("a:has-text('ASSET-8')").get_attribute("href") == created["issue_url"]
    assert errors == [], errors


# --- executive dashboard -------------------------------------------------------------------------

def test_dashboard_is_the_home_page_and_links_to_filtered_findings(page, live_server, errors):
    _login(page, live_server, "viewer")
    errors.clear()                                      # ignore the pre-login /auth/me 401 from sign-in
    page.goto(f"{live_server}/#/")
    page.wait_for_selector(".kpi-grid")
    assert page.locator(".kpi").count() == 5
    assert page.locator("#mainnav a.active").inner_text() == "Dashboard"
    text = page.inner_text("main")
    # empty database: unavailable states, never invented values
    assert "Unavailable" in text and "no asset with software data has been assessed yet" in text
    assert "Overdue remediation actions" in text and "not recorded by the application" in text
    page.click('.kpi:has-text("Open critical findings") a.kpi-link')
    page.wait_for_selector("#fresults")
    assert "risk level CRITICAL" in page.inner_text(".notice")
    assert errors == [], f"console/page errors: {errors}"


def test_leaving_the_dashboard_while_it_loads_keeps_the_next_page(page, live_server, errors):
    """The dashboard renders into the main view: a late answer must not overwrite the next page."""
    page.add_init_script(r"""
        const fetch0 = window.fetch;
        window.__delayed = 0;
        window.fetch = (url, opts) => /\/(dashboard|findings|correlation)\b/.test(String(url))
            ? (window.__delayed++, new Promise((r) => setTimeout(r, 400)).then(() => fetch0(url, opts)))
            : fetch0(url, opts);
    """)
    _login(page, live_server, "admin")
    errors.clear()
    for route in ("#/dashboard", "#/findings", "#/assessments", "#/assets"):
        page.evaluate(f"location.hash = '{route}'")
        page.wait_for_timeout(100)                      # leave before the delayed answer arrives
    page.wait_for_timeout(800)
    assert page.evaluate("window.__delayed") >= 3
    assert errors == [], f"console/page errors: {errors}"
    assert page.locator(".kpi-grid, #fresults, #schedule").count() == 0    # still on the assets page
    assert page.locator("input[name='q']").count() == 1


def test_findings_search_field_filters_as_you_type(page, live_server, errors):
    seen = []

    def findings(route):
        seen.append(route.request.url)
        q = "2011-2523" in route.request.url
        items = [_finding(1), _finding(2)] if q else [_finding(1), _finding(2), _finding(3)]
        route.fulfill(json={"total": len(items), "limit": 200, "offset": 0, "items": items})

    page.route("**/findings?*", findings)
    _login(page, live_server, "viewer")
    errors.clear()                                      # ignore the pre-login /auth/me 401 from sign-in
    page.goto(f"{live_server}/#/findings")
    page.wait_for_selector("text=3 findings")
    page.fill("#ffilters input[name='q']", "2011-2523")
    page.wait_for_selector("text=2 findings")
    assert any("q=2011-2523" in u for u in seen)
    assert "q=2011-2523" in page.url                     # kept in the address (reload / share)
    page.reload()
    page.wait_for_selector("text=2 findings")
    assert page.input_value("#ffilters input[name='q']") == "2011-2523"
    assert errors == [], errors

# CyberAsset Guard — Jira Backlog

Generated 2026-10-13 from the repository `the project repository`. **No Jira issues were created**: no Jira
integration (MCP connector, CLI or API credentials) is available in this environment. This document and
`jira-import.csv` form an import-ready backlog.

Legend: ✅ **verified** = checked in code and/or by running tests · *(estimate)* = story points or effort
are estimates · **assumption** = not verifiable from the repository.

## 1. Current implementation assessment

### Repository state (verified)

| Ref | Branch | Where | Content | Tests |
|---|---|---|---|---|
| `ff0dbc7` | `main` (= `origin/main`, `origin/monitoring-part5`) | GitHub | Monitoring parts 1–5, Asset Management, infrastructure | **87 tests: 86 passed, 1 skipped** (Docker test, opt-in) — run 2026-10-13 |
| `453d973` | `feature/auth-rbac-audit` | **local only, not pushed, not reviewed** | + login, RBAC, audit log | **154 tests passed incl. Docker** — run 2026-10-13 |
| `ae26506` | `feature/correlation-risk-action` | local only | unreviewed prototype of correlation/risk/Jira (old data model) | not on main; **not counted as done** |

Stack (verified): Python ≥ 3.11 (tested on 3.13), FastAPI, SQLAlchemy 2 (assets, auth, audit) + plain
`sqlite3` (Monitoring), SQLite single file, APScheduler, Nmap via subprocess, static HTML/JS/CSS UI without
build step, Docker + Compose. ~4,250 lines in `app/`.

### Completed work (verified — no new stories created)

| Area | Implemented | Evidence |
|---|---|---|
| Monitoring (block 2) | Nmap discovery, port scan, version scan, scheduled scans (persisted), change detection, CLI | `app/monitoring/*`, commits `c7c2ae8`…`d68d855`; **only indirectly tested** (see gaps) |
| Asset inventory (block 1) | UUID identity, required/optional fields with controlled values (API + DB CHECK constraints), tags table, create/list/search/filter/sort/page/get/update, deactivate/activate (no delete), web UI (overview, detail with 6 sections, add/edit form, validation messages) | `app/assets/*`, `app/web/*`, `tests/test_assets.py` (50 tests incl. parametrised) |
| Infrastructure | Config validation with clear errors, `.env.example`, runtime/dev requirements + `constraints.txt`, liveness/readiness endpoints, logging, generic error responses, `busy_timeout`, `python -m app.maintenance` (check, init-db, backup via SQLite online backup, verify, restore without silent overwrite), Dockerfile (non-root, healthcheck), Compose (localhost port, data + backup volumes) | `tests/test_infrastructure.py` (37 tests incl. real Uvicorn restart and Docker test) |
| Authentication & access (branch only) | scrypt hashing, password policy, server-side sessions (HttpOnly/SameSite=Strict, token hash stored), idle + absolute expiry, lockout, no user enumeration, RBAC viewer/analyst/admin on all endpoints, last-admin protection, user management API + UI, CLI create-user/reset-password | `app/auth/*`, `tests/test_auth.py` (54 tests) — **on `feature/auth-rbac-audit` only → story `S2.1`** |
| Audit log (branch only) | Append-only (DB triggers), logins/lockouts/passwords/users/assets (field diff, same transaction)/monitoring/denied/CSRF, redaction, admin UI + API with filters | `app/audit/*`, `tests/test_audit.py` (13 tests) — **branch only → `S2.1`** |

### Remaining gaps and technical debt (verified in code)

| Gap | Evidence | Backlog |
|---|---|---|
| **Nmap argument injection**: scan targets are split on whitespace and passed to nmap unvalidated; a token starting with `-` becomes an nmap option | `app/monitoring/scanner.py` lines 168–227 (code review; not exploited — nmap not installed here) | `B4.1` |
| No restriction of scan targets to authorised networks | no allow-list in `app/monitoring` | `S4.1` |
| Schedules accept `interval_seconds >= 1`; Monitoring list `limit` unbounded | `app/monitoring/routes.py` | `B4.2` |
| No authentication on `main` (fixed on unmerged branch) | `main` routes have no auth dependency | `S2.1` |
| Monitoring hosts (`assets` table, keyed by IP) not linked to `asset_inventory` | no reference to `asset_inventory` in `app/monitoring` | `S4.2`, `S4.3` |
| No dedicated Monitoring tests (XML parsing, diff, scheduler, errors) | no test targets `app/monitoring`; only a smoke test and fake-scanner use | `S8.1` |
| No CI, lint, format, type checks, `.gitattributes` (CRLF warnings) | no `.github/`, `pyproject.toml`, `ruff`/`mypy` config | `S1.1`, `S1.3` |
| No schema migrations (`create_all` cannot alter tables) | no Alembic | `S1.2` |
| Two data-access styles (sqlite3 vs SQLAlchemy) | `app/db.py` vs `app/database.py` | `S1.5` |
| Nmap missing in Docker image | `Dockerfile` comment line 3 | `T4.5` |
| UI only tested manually | no browser tests | `S8.4` |
| No TLS profile; manual backups without retention; no audit retention | README limitations | `S9.1`, `S9.2`, `S2.6` |
| Only per-account lockout, no IP rate limit; admin-set passwords not force-changed; no API tokens | `app/auth/service.py` | `S2.2`, `S2.3`, `S2.4` |
| Distribution backports cause false positives (future CVE matching) | design limitation | `S5.6` |

### Assumptions

- The Jira project uses the standard issue types **Epic, Story, Task, Bug, Sub-task** and the priority
  scheme **Highest/High/Medium/Low**. *(assumption — verify before import)*
- Story points field exists (company-managed: "Story Points"; team-managed: "Story point estimate"). *(assumption)*
- Story points are relative estimates for a team familiar with the code base; they are **not** commitments.
- Blocks 3–5 (Vulnerability, Risk, Remediation) follow the original design slides; the local prototype branch
  is reference material only.

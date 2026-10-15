# CyberAsset Guard

Lightweight, asset-centric cybersecurity platform (MVP). Implements the design in `image/image.png`:

> **Asset Inventory** → **Monitoring** → **Vulnerability Correlation** → Contextual Risk → Remediation

| Block | Status |
|-------|--------|
| 1 — Asset Management | ✅ done |
| Security — login, roles (RBAC), audit log | ✅ done |
| 2 — Monitoring (Nmap) | ✅ module available; not yet linked to managed assets |
| 3 — Vulnerability correlation (NVD, CISA KEV, findings) | ✅ API available; UI follows (S5.5) |
| 4–5 — Risk, remediation | ⏳ later steps |

## Stack
- Python 3.11+ · FastAPI (API + OpenAPI docs)
- SQLite (single database file for the whole application)
- SQLAlchemy 2 (Asset Management) · plain `sqlite3` (Monitoring)
- Lightweight web UI: static HTML/CSS/JS served by FastAPI, no build step
- Nmap (Monitoring scanning engine, via subprocess + XML output)

## Requirements
- Python **3.11 or newer** (tested with 3.11 and 3.14; the Docker image uses 3.14). Checked on startup.
- Runs on Windows, macOS and Linux. No external services are needed for Asset Management.
- The `nmap` binary is only needed for the Monitoring module. Install it yourself for local runs; the Docker image already includes it.

| File | Purpose |
|------|---------|
| `requirements.txt` | runtime dependencies (version ranges) |
| `requirements-dev.txt` | + test tools (`pytest`, `httpx`, `packaging`) |
| `constraints.txt` | exact versions the tests were run with; used by Docker |

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt -c constraints.txt     # runtime only: requirements.txt
cp .env.example .env                 # optional - defaults work without it
python -m app.maintenance check      # validates Python version, paths, settings
python -m app.maintenance create-user admin --role admin   # first administrator (prompts for a password)
```
There is no self-registration: the first administrator is created on the server, further users
by an administrator in the web UI (**Users**) or with `create-user`.

## Run
```bash
uvicorn app.main:app --env-file .env          # or without --env-file to use the defaults
uvicorn app.main:app --env-file .env --reload # local development only (auto-reload)
```
- **Web UI:** http://127.0.0.1:8000/
- **API docs (Swagger):** http://127.0.0.1:8000/docs (ReDoc: `/redoc`)
- **Health:** `/health/live` (liveness, alias `/health`) · `/health/ready` (readiness, checks the database)

The database and all tables are created automatically on startup (or explicitly with
`python -m app.maintenance init-db`). Run from the project root when using relative paths.

## Code quality (linting, formatting, type checking)
Tooling is configured in `pyproject.toml` and installed with the dev dependencies
(`pip install -r requirements-dev.txt -c constraints.txt`).

```bash
ruff check                 # lint (includes flake8-bandit "S" security rules)
ruff check --fix           # lint and auto-fix what is safe
ruff format                # apply the formatter
mypy                       # type-check app/assets, app/auth, app/audit
```

- **ruff** owns both linting and line length (120); the formatter is the source of truth for layout.
- **mypy** type-checks the core packages; Monitoring starts relaxed and can be tightened later.
- **pre-commit** runs ruff and basic hygiene hooks on every commit — install it once:
  ```bash
  pip install pre-commit && pre-commit install
  pre-commit run --all-files     # optional: run against the whole tree
  ```
- `.gitattributes` normalises text files to **LF** on all platforms.
- CI runs `ruff check` and `mypy` on every push/PR and fails on any violation.

## Configuration
All settings are environment variables (template: `.env.example`; `.env` is git-ignored).
The application needs **no secrets or API keys**; user passwords live (hashed) in the database.

| Variable | Default | Meaning |
|----------|---------|---------|
| `CAG_DB_PATH` | `./cyberasset_guard.db` | SQLite database file (directory is created if missing) |
| `CAG_DATABASE_URL` | – | shared database server instead of SQLite, e.g. Azure PostgreSQL: `postgresql+psycopg://user:pass@host:5432/db?sslmode=require` (keep it in `.env` only) |
| `CAG_BACKUP_DIR` | `./backups` | target of `python -m app.maintenance backup` — keep it apart from the database |
| `CAG_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `CAG_SESSION_IDLE_MINUTES` | `30` | session ends after this much inactivity |
| `CAG_SESSION_MAX_HOURS` | `12` | … and at the latest this long after login |
| `CAG_COOKIE_SECURE` | `false` | `true` = session cookie only over HTTPS — **set it whenever TLS is used** |
| `CAG_LOGIN_MAX_FAILURES` / `CAG_LOGIN_LOCKOUT_MINUTES` | `5` / `15` | account lockout after failed logins |
| `CAG_TRUSTED_ORIGINS` | – | extra origins allowed to send changes (comma-separated), e.g. behind a reverse proxy |
| `CAG_BACKUP_INTERVAL_HOURS` | `0` (Docker: `24`) | automatic verified backups every N hours; `0` = off |
| `CAG_BACKUP_KEEP_DAILY` / `CAG_BACKUP_KEEP_WEEKLY` | `7` / `4` | backup retention (newest per day / per ISO week) |
| `CAG_SCAN_ALLOWED_NETWORKS` | private + loopback ranges | CIDRs that may be scanned; everything else is refused (403, audit-logged); `any` disables the check |
| `CAG_SCAN_MIN_INTERVAL_SECONDS` | `900` | shortest interval for scheduled scans |
| `CAG_SCAN_MAX_CONCURRENT` | `2` | max scans running at once; further requests get HTTP 429 |
| `CAG_NMAP_BIN`, `CAG_SCAN_TIMEOUT` | `nmap`, `300` | Monitoring module only |
| `CAG_NVD_API_KEY` | – | optional [NVD API key](https://nvd.nist.gov/developers/request-an-api-key): NVD rate limit 50 instead of 5 requests / 30 s; sent only to NVD, never logged |
| `CAG_NVD_CACHE_HOURS` | `24` | how long downloaded CVE data per product is reused |
| `CAG_CORRELATION_INTERVAL_HOURS` | `24` | refresh KEV + changed CVEs and re-correlate all assets every N hours; `0` = off |
| `CAG_CORRELATION_AFTER_SCAN` | `true` | correlate scanned assets automatically after each version scan |

## Security: login, roles and audit log

### Login and sessions
- Username + password. Passwords are hashed with **scrypt** (salted, memory-hard; Python stdlib);
  policy: 12–128 characters, must not contain the username. Hashes are upgraded automatically
  on login when the cost parameters are raised.
- Server-side sessions; the cookie `cag_session` is `HttpOnly`, `SameSite=Strict` (and `Secure`
  with `CAG_COOKIE_SECURE=true`). Only a SHA-256 hash of the token is stored.
- Sessions end on logout, after the idle timeout or the maximum lifetime, and immediately when the
  user is disabled or their role changes. Changing/resetting a password ends the other sessions.
- After `CAG_LOGIN_MAX_FAILURES` wrong passwords the account is locked for
  `CAG_LOGIN_LOCKOUT_MINUTES`. Failed logins always return the same message ("Invalid username or
  password") with the same timing, whether the user exists, is locked or disabled.
- CSRF: `SameSite=Strict` cookies **and** an `Origin`/`Referer` check on every state-changing
  request. Responses carry `Content-Security-Policy`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`; API responses are `Cache-Control: no-store`.

### Roles and permissions
| Permission | Viewer | Analyst | Administrator |
|------------|:------:|:-------:|:-------------:|
| `assets:read` — view assets | ✅ | ✅ | ✅ |
| `assets:write` — create, edit, deactivate/reactivate assets | | ✅ | ✅ |
| `monitoring:read` — view scans, changes, schedules | ✅ | ✅ | ✅ |
| `monitoring:run` — run scans, manage schedules | | ✅ | ✅ |
| `findings:read` — view findings and correlation runs | ✅ | ✅ | ✅ |
| `findings:write` — run correlation, change finding status, accept risks | | ✅ | ✅ |
| `users:manage` — users, roles, password resets | | | ✅ |
| `audit:read` — audit log | | | ✅ |

Public without login: the web UI shell and static files, `/health/*`, `/docs`, `/openapi.json`,
`/auth/login`, `/auth/status`. The last active administrator cannot be demoted or disabled.
The UI hides actions a role may not use; the API enforces every permission regardless.

### Audit log
Append-only table `audit_events` (database triggers reject `UPDATE`/`DELETE`; the API has no
write endpoints). Each entry: time (UTC), user, IP address, action, outcome
(`success`/`failure`/`denied`), target and details.

| Actions | Recorded |
|---------|----------|
| `auth.login`, `auth.logout`, `auth.lockout`, `auth.password_change` | every sign-in attempt with reason on failure (wrong password, unknown user, locked, disabled) |
| `user.create`, `user.update`, `user.role_change`, `user.disable`, `user.enable`, `user.password_reset` | with before/after values |
| `asset.create`, `asset.update`, `asset.deactivate`, `asset.activate` | field-level diff (`from` → `to`), written in the **same transaction** as the change |
| `monitoring.discover`, `.portscan`, `.versionscan`, `.schedule_create`, `.schedule_delete` | who started which scan, HTTP status |
| `finding.update`, `finding.accept_risk`, `correlation.run`, `correlation.kev_refresh` | status changes with before/after values; who started correlation |
| `finding.auto_close`, `finding.auto_reopen` | status changes made by correlation itself (user `system`), with before/after values |
| `asset.software_add`, `asset.software_remove` | manually entered software of an asset |
| `access.denied`, `access.csrf_rejected` | requests blocked by RBAC or the origin check |

Passwords and tokens are never written to the audit log (and are redacted if a key named like
one appears); long values are truncated. CLI actions are attributed to `cli:<OS user>`.
Administrators browse and filter it under **Audit log** or via `GET /audit`
(`action` — exact or prefix like `auth.*`, `actor`, `outcome`, `target_type`, `target_id`, `since`, `until`).

### Demo / test data (Cybermock)
A complete demo inventory of **Cybermock Solution GmbH** — a *fictional* company used in our training
material — can be loaded through the normal service layer (validated, audit-logged as `cli:<OS user>`):
```bash
python -m app.maintenance seed-demo                                   # local
docker compose exec app python -m app.maintenance seed-demo           # Docker
```
73 assets: on-premises AD `cybermock.local` (domain controller, Entra Connect, file/print, HR system,
SIEM, backup, firewall, VPN, network), ~40 Windows endpoints (many remote) incl. the laptop from
incident INC-2031 as *inactive*, and the **Azure** estate (Entra ID tenant, App Services, Application
Gateway, Azure SQL, storage accounts `cminsights544g9v` / `labscripts45thai` from the cloud audit, Key
Vault, AKS, ACR, Functions, Log Analytics, Recovery vault, Bastion, VMs). Cloud metadata is stored as
tags (`cloud`, `provider:azure`, `subscription:…`, `rg:…`, `region:…`, `azure:<type>`); audit findings
as `finding:…`. Every asset is tagged `demo:cybermock`; re-running the command creates no duplicates.
All IP addresses are private or documentation ranges. Filter in the UI or API, e.g.
`GET /assets?tag=provider:azure`.

### Account administration on the server
```bash
python -m app.maintenance create-user jdoe --role analyst --display-name "Jane Doe"
python -m app.maintenance reset-password admin      # locked out? new password, unlocked, re-enabled
python -m app.maintenance list-users
echo "$PASSWORD" | python -m app.maintenance create-user admin --role admin --password-stdin   # scripts
```

### API authentication
The API uses the same session cookie as the UI:
```bash
curl -c jar -H 'content-type: application/json' -d '{"username":"admin","password":"…"}' localhost:8000/auth/login
curl -b jar localhost:8000/assets
curl -b jar -X POST localhost:8000/auth/logout
```
`GET /auth/me` returns the current user and permissions. In Swagger UI (`/docs`) log in via
`POST /auth/login` first; the browser then sends the cookie automatically.

Invalid values stop the application at startup with a message naming the variable, e.g.
`ConfigError: CAG_SCAN_TIMEOUT must be an integer, got 'abc'`.

## Operations

### Health checks
| Endpoint | Meaning | Status |
|----------|---------|--------|
| `GET /health/live` (`/health`) | process is up and serving — no dependency checks | always `200` |
| `GET /health/ready` | database reachable **and** schema present | `200` `{"status":"ready"}` or `503` `{"status":"not_ready"}` |

Responses contain no paths, versions or error details.

### Logging
Application logs go to stderr (`timestamp LEVEL logger: message`); Uvicorn adds its access log.
Logged: startup (version, database path), startup failures with the reason, shutdown, unexpected
errors and database errors with stack traces. API clients only ever get generic messages
(`"Internal server error."`, `"A database error occurred. …"`). Request bodies are not logged.

### Shared database (PostgreSQL / Azure)
By default every installation uses its own SQLite file. To let the whole team work on **one**
database, point `CAG_DATABASE_URL` at a PostgreSQL server (we use Azure Database for PostgreSQL
Flexible Server, Germany West Central). All modules — assets, users, audit log and Monitoring —
use it; the audit log is append-only there as well (trigger blocks `UPDATE`, `DELETE`, `TRUNCATE`).

```bash
# .env (never commit it)
CAG_DATABASE_URL=postgresql+psycopg://<app-user>:<password>@<server>.postgres.database.azure.com:5432/cyberasset_test?sslmode=require

python -m app.maintenance check            # shows the server (password masked) and whether it is ready
python -m app.maintenance init-db          # creates the schema on the server (idempotent)
python -m app.maintenance copy-to-server cyberasset_guard.db   # one-off: move existing SQLite data (target must be empty)
```
- Access to the Azure test server: TLS is enforced and the firewall only admits listed IP addresses —
  ask an admin to add yours. Credentials are shared through the password manager, never via Git,
  chat or tickets.
- Backups: the server is backed up by Azure (automated backups, point-in-time restore); the file
  commands `backup` / `restore` / scheduled backups apply to SQLite only and refuse a server URL.
- Tests: `CAG_TEST_DATABASE_URL=<disposable PostgreSQL database> pytest` runs the whole suite against
  PostgreSQL (each test drops and recreates the `public` schema — never point it at shared data).
  Locally: `docker run -d -p 127.0.0.1:55432:5432 -e POSTGRES_USER=cag -e POSTGRES_PASSWORD=<pw> -e POSTGRES_DB=cag_test postgres:16-alpine`.

### Database initialization and migrations
- The schema is managed by **Alembic**. On startup the application runs `alembic upgrade head`
  automatically (`app/database.ensure_schema`): a new database is created at the latest revision,
  and a database behind the latest revision is upgraded in place. If a migration fails, startup
  aborts with a logged error rather than serving against a half-migrated schema.
- Migrations never drop data, but **back up first** before upgrading a database with real data:
  `python -m app.maintenance backup`.
- The baseline revision (`alembic/versions/0001_baseline.py`) reproduces the original pre-Alembic
  schema exactly — the same tables, indexes, CHECK constraints and the `audit_events` append-only
  triggers (SQLite and PostgreSQL) — by delegating to the ORM models (`create_all`).
  Because the baseline always reflects the *current* models, a fresh database already has every
  column when later revisions run: **write each later migration conditionally** (add a column or
  index only if it is missing - see `0002_link_hosts_to_assets.py`).
- The same migrations run on SQLite and on a database server (`CAG_DATABASE_URL`). To migrate
  without starting the app: `python -m app.maintenance init-db` (uses the configured database;
  the `alembic` CLI uses the same configured database).
- **Adopting an existing (pre-Alembic) database:** it is stamped automatically on first startup —
  the baseline is create-if-not-exists, so it only records the revision without touching data. To
  do it manually instead: `alembic stamp head` (run from the project root).
- **Making a schema change:** edit the models, run `alembic revision --autogenerate -m "..."`,
  review the generated script (SQLite column changes use Alembic *batch* mode), and commit it. The
  next startup (or `alembic upgrade head`) applies it.
- SQLite connections use `foreign_keys=ON` and a 5 s `busy_timeout` (scheduler threads and
  requests share the file).

### Backup and restore
Backups use SQLite's online backup API, so they are consistent even while the app is running
(copying the live file is **not** safe). Every backup is integrity-checked before it is kept.

```bash
python -m app.maintenance backup                       # -> $CAG_BACKUP_DIR/cyberasset_guard-<UTC>.db
python -m app.maintenance verify backups/cyberasset_guard-20261012T205648Z.db

# Test a restore in isolation (never touches the active database):
python -m app.maintenance restore backups/cyberasset_guard-20261012T205648Z.db --target restore-test/cag.db

# Real restore: stop the application first, then
python -m app.maintenance restore backups/cyberasset_guard-20261012T205648Z.db \
    --target cyberasset_guard.db --force
```
Restore refuses to overwrite an existing file unless `--force` is given; with `--force` the
current database is first saved as `<name>.pre-restore-<UTC>.db`. Restoring over a database that
is still open fails with "is in use - stop the application" on Windows; on Linux and macOS
the file *can* be replaced while open, so always stop the application first.

**Scheduled backups and retention.** With `CAG_BACKUP_INTERVAL_HOURS` > 0 (Docker default: `24`,
local default: off) the application itself writes a verified backup 5 minutes after start and then
every N hours, and applies the retention policy: the newest backup of each of the last
`CAG_BACKUP_KEEP_DAILY` days (7) and of each of the last `CAG_BACKUP_KEEP_WEEKLY` ISO weeks (4);
the newest backup is always kept and files not written by `backup` are never touched. Results and
failures are logged. Retention can also be run by hand:
```bash
python -m app.maintenance prune-backups [--keep-daily 7] [--keep-weekly 4]
```
Backups on the same disk are not enough on their own: copy the backup directory off the host
regularly (e.g. `azcopy sync /backups https://<account>.blob.core.windows.net/cag-backups` with an
immutability/retention policy on the container), and restore one backup into a test path
quarterly to prove it works (`restore … --target restore-test/cag.db`).

### Docker (optional)
Docker is not required. It gives a reproducible runtime with persistent storage.
Run all commands from the project root (the folder containing `docker-compose.yml`).

#### Start
```bash
docker compose up -d --build          # build the image and start in the background
docker compose ps                      # STATUS shows (healthy) once /health/ready answers
```
Then open http://127.0.0.1:8000. Use another host port with `CAG_PORT=8080 docker compose up -d`
(PowerShell: `$env:CAG_PORT=8080; docker compose up -d`).

The image ships with `nmap`, so the Monitoring scans work inside the container. They run as
the unprivileged user (uid 10001) using nmap's TCP connect scan (`-sT`); SYN/UDP/OS-detection
scans are not available because the container is not granted the `NET_RAW`/`NET_ADMIN`
capabilities (and should not be).

First start only — create the first administrator (prompts for a password):
```bash
docker compose exec app python -m app.maintenance create-user admin --role admin
```

#### Stop
```bash
docker compose stop                    # stop the container, keep it (resume with: docker compose start)
docker compose down                    # stop and remove the container; data volumes are kept
```
`docker compose up -d` starts it again with all data. **`docker compose down -v` also deletes the
volumes, i.e. the database and backups** — only use it to wipe everything.

#### Restart, update, logs
```bash
docker compose restart app             # restart the running container
docker compose up -d --build           # after code changes: rebuild and recreate (data is kept)
docker compose logs -f app             # follow the application logs (Ctrl+C to exit)
```

#### Backups
The container writes a backup every 24 h with retention (7 daily / 4 weekly) — see *Scheduled
backups and retention*. Manual backup and copy to the host:
```bash
docker compose exec app python -m app.maintenance backup
docker compose cp app:/backups ./backups          # copy backups to the host
```

#### HTTPS (TLS profile)
For anything beyond localhost, run the HTTPS profile: Caddy terminates TLS (TLS 1.2/1.3, HSTS,
HTTP → HTTPS redirect) and the app port is no longer published. The app automatically runs with
`CAG_COOKIE_SECURE=true` and `CAG_TRUSTED_ORIGINS=https://$CAG_DOMAIN` and trusts the proxy's
`X-Forwarded-*` headers (so audit logs show the real client IP).
```bash
# internal host, certificate from Caddy's own CA (import its root certificate on clients):
CAG_DOMAIN=cag.cybermock.local docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d --build
# public host name, Let's Encrypt certificate (ports 80/443 must be reachable from the internet):
CAG_DOMAIN=cag.cybermock.io CAG_TLS=admin@cybermock.io docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d --build
# stop
docker compose -f docker-compose.yml -f docker-compose.tls.yml down
```
PowerShell: set the variables first, e.g. `$env:CAG_DOMAIN="cag.cybermock.local"`. Optional:
`CAG_HTTPS_PORT` / `CAG_HTTP_PORT` (default 443 / 80) and `CAG_HTTPS_BIND` / `CAG_HTTP_BIND`
(default `0.0.0.0`). Restrict who can reach port 443 with the host firewall / Azure NSG.
Requires Docker Compose 2.24 or newer.

- One container (plus Caddy in the TLS profile), non-root user (uid 10001), no `--reload`, health
  check on `/health/ready`.
- Volumes: `cag-data` → `/data` (database), `cag-backups` → `/backups` (backups, separate volume),
  `caddy-data` (certificates, TLS profile only). Data survives `down`/`up` and `--force-recreate`.
- Without the TLS profile the port is bound to `127.0.0.1` only — do not expose plain HTTP.
- The image contains no `.env` and no secrets; Nmap is not installed (Monitoring scans return
  "nmap binary not found" in the container).

## Tests
```bash
pytest                                  # all tests, each with its own temporary database
CAG_TEST_DOCKER=1 pytest -k docker      # + Docker deployment tests incl. HTTPS profile (needs Docker)
python -m playwright install chromium   # one-time, for the UI e2e tests
CAG_TEST_E2E=1 pytest tests/test_e2e_ui.py   # + headless browser tests of the web UI (ASSET-83)
```
The Docker and e2e suites are opt-in (the env vars above) so the default `pytest` run needs no
browser or Docker. The e2e tests start a throwaway server + database and drive Chromium headless.
**CI:** `.github/workflows/ci.yml` runs on every push to `main` / `feature/**` and on pull requests:
pytest on Python 3.11 (documented minimum) and 3.14, then the Docker deployment tests. Actions are
pinned to commit SHAs and the workflow only has read access. To block merges on failing tests,
enable branch protection for `main` with the required checks `pytest (Python 3.11)`,
`pytest (Python 3.14)` and `Docker deployment` (GitHub → Settings → Branches; repository admin).
`tests/test_assets.py` covers the Asset Management API; `tests/test_auth.py` login, sessions,
lockout, password handling, the permission matrix, user management, CSRF and security headers;
`tests/test_audit.py` audit completeness, diffs, atomicity, redaction and append-only storage;
`tests/test_infrastructure.py` dependencies, configuration, database, startup (incl. a real
Uvicorn process restart), health checks, persistence, error handling, backup/restore and Docker.

## Dependency updates
`.github/dependabot.yml` configures **Dependabot** to open weekly pull requests for three
ecosystems:
- **pip** — the packages in `requirements.txt` / `requirements-dev.txt` (grouped into one PR),
- **docker** — the `python:3.14-slim` base image in the `Dockerfile`,
- **github-actions** — the pinned action SHAs in `.github/workflows`.

CI runs on every Dependabot PR and must pass before merge. The dependency checks in
`tests/test_infrastructure.py` (`test_declared_dependencies_are_installed_in_range`,
`test_constraints_are_consistent_with_requirements`) fail the build if `constraints.txt` drifts
from `requirements*.txt`, so an update cannot land with inconsistent pins.

**Regenerating `constraints.txt` (on Linux, to match the Docker image and CI).** The committed
pins were originally produced on Windows; refresh them in a Linux environment — easiest inside the
runtime image so the versions match production:
```bash
docker run --rm -v "$PWD":/w -w /w python:3.14-slim bash -c '
  pip install -q -U -r requirements-dev.txt &&
  pip freeze --exclude-editable' > constraints.txt
```
Then review the diff (pay attention to the changelogs of security-relevant packages such as
`fastapi`, `starlette` and `sqlalchemy`), run `pytest`, and open a PR so CI validates it.

## Security scanning (CI)
Three layers run in CI (ASSET-81), on every PR/push and **weekly** on `main` (scheduled):
- **Static analysis** — ruff's flake8-bandit (`S`) rules, in the `lint` job (see `pyproject.toml`).
- **Dependency vulnerabilities** — `pip-audit` over the pinned runtime set (`requirements.txt -c constraints.txt`).
- **Container image** — `Trivy` scans the built Docker image.

`pip-audit` and Trivy run in the `security` job. **HIGH/CRITICAL findings fail the build** unless
explicitly waived. Each scan uploads its report as a CI artefact (`pip-audit-report`,
`trivy-report`). Trivy uses `--ignore-unfixed`, so only vulnerabilities with an available fix fail.

**Waivers** are listed in `.trivyignore` (CVE ids) and `security/pip-audit-ignores.txt` (advisory
ids). Every waiver must carry a **reason and an expiry date** and be reviewed at/ before expiry —
keep both lists short. To verify detection works, pin a known-vulnerable version on a test branch
and confirm the `security` job fails.

## Asset Management

Every asset is a persistent security object with its own identity, ownership, environment,
criticality and lifecycle status.

### Web UI
- **Assets** overview: name, IP address, hostname, asset type, environment, criticality,
  internet exposure, lifecycle status, last updated. Search (name / IP / hostname) and filters
  (environment, criticality, asset type, internet-facing, status). Shows active assets by default.
- **Add Asset** form with server-side validation messages per field; warns when the name is
  already used (names are not unique — the short asset ID, IP and hostname tell assets apart).
- **Asset detail** page: General Information, Ownership, Business Context, Environment and
  Criticality, Network Identification, Lifecycle Information. Future modules plug in additional
  sections (`DETAIL_SECTIONS` in `app/web/static/app.js`).
- **Edit** and **Deactivate / Reactivate** (with confirmation).

### Data model
| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID (v4) | generated by the server; independent of IP / hostname; never changes |
| `name` | string, required | max 200, not unique |
| `asset_type` | required | `server`, `workstation`, `laptop`, `virtual_machine`, `container`, `network_device`, `database`, `web_application`, `cloud_resource`, `other` |
| `environment` | required | `development`, `test`, `staging`, `production` |
| `criticality` | required | `low`, `medium`, `high`, `critical` |
| `internet_facing` | optional | `yes`, `no`, `unknown` (default) |
| `ip_address` | optional | validated IPv4 / IPv6, stored normalized |
| `hostname` | optional | validated, stored lower-case |
| `owner`, `description` | optional | |
| `tags` | optional list | separate `asset_tags` table, lower-case, max 20 |
| `status` | `active` / `inactive` | new assets are `active` |
| `created_at`, `updated_at`, `deactivated_at` | UTC timestamps | `created_at` is immutable; `updated_at` changes only when something actually changed |

Tables: `asset_inventory` and `asset_tags`. Controlled values are enforced by the API **and** by
database CHECK constraints. Later modules (monitoring results, services, findings) reference
`asset_inventory.id`, which is why assets are deactivated instead of deleted.

### API
| Method & path | Purpose |
|---------------|---------|
| `POST /assets` | create an asset (201) |
| `GET /assets` | list / search / filter: `q`, `environment`, `criticality`, `asset_type`, `status`, `internet_facing`, `tag`, `sort` (`updated`, `name`, `criticality`), `limit` (≤ 500), `offset` |
| `GET /assets/{id}` | one asset (404 if unknown) |
| `PATCH /assets/{id}` | partial update; omitted fields stay unchanged, `null` clears optional fields; `id` / `created_at` cannot be changed |
| `POST /assets/{id}/deactivate` · `POST /assets/{id}/activate` | lifecycle; the record is always kept |
| `GET /assets/options` | allowed values + display labels |

There is intentionally no `DELETE`. Validation errors return 422 with a message per field;
database errors return a generic 500 message (details are only logged server-side).

Reading needs `assets:read`, all changes `assets:write` (see *Roles and permissions*).

```bash
# after logging in with: curl -c jar ... /auth/login (see "API authentication")
curl -b jar -X POST localhost:8000/assets -H 'content-type: application/json' -d '{
  "name": "web-prod-01", "asset_type": "web_application", "environment": "production",
  "criticality": "critical", "ip_address": "10.0.4.12", "internet_facing": "yes",
  "owner": "Platform Team", "tags": ["pci", "dmz"]}'
curl -b jar 'localhost:8000/assets?q=web&environment=production&criticality=critical'
```

### Known limitations (MVP)
- Login, RBAC and audit logging are in place, but the application is **not** production-hardened
  and has not had an external security review. Not yet included: TLS termination (use a reverse
  proxy), multi-factor authentication, SSO/LDAP, API tokens for automation, IP-based rate limiting
  (only per-account lockout), audit-log retention/export and forwarding to a SIEM.
- Anyone with shell access to the server is outside the RBAC model: the database file, the
  maintenance commands and the Monitoring `cli.py` work directly on the database (CLI scans via
  `cli.py` are not audit-logged; `app.maintenance` user changes are, as `cli:<OS user>`).
- The audit log stores IP addresses and usernames (personal data): define a retention period.
- SQLite + in-process scheduler: run a single Uvicorn worker / single container.
- Backups are scheduled with retention, but the off-host copy is an operational step (see above).
- The Monitoring web UI (candidate hosts view, "create asset from host" form) is not built yet;
  host ↔ asset linking is available via the API (see *Monitoring module*).

## Monitoring module (block 2)
| Part | Feature | Status |
|------|---------|--------|
| 1 | Nmap discovery / reachability | ✅ done |
| 2 | Open ports & services | ✅ done |
| 3 | Software / versions | ✅ done |
| 4 | Scheduled scans | ✅ done |
| 5 | Change detection | ✅ done |

### Linking discovered hosts to managed assets
Discovered hosts (the `assets` table, keyed by IP) are linked to managed assets
(`asset_inventory`, by UUID) so monitoring data belongs to the right asset. **Matching rule:** a
host is matched to **active** managed assets by exact IP address, then (if no IP match) by exact
host name — exactly one match links automatically, more than one is *ambiguous* and left for an
analyst. The link is by asset id, so an asset's IP can change without breaking it. Linking and
unlinking are audit-logged; linking/creating requires `assets:write`.

```
GET  /monitoring/candidates              # unmanaged hosts + suggested matches
POST /monitoring/hosts/{id}/link         # {"asset_id": "..."}   (assets:write)
POST /monitoring/hosts/{id}/unlink       # (assets:write)
POST /monitoring/hosts/{id}/create-asset # asset fields -> creates + links (assets:write)
```
The candidate-hosts **web UI** and "create asset from host" form are a separate follow-up (ASSET-96).

### Quick test (CLI, no server needed)
```bash
python cli.py discover 127.0.0.1       # Part 1: ping scan, stores results
python cli.py portscan 127.0.0.1 -p 1-1024     # Part 2: open ports & services
python cli.py versionscan 127.0.0.1 -p 22,80,443  # Part 3: service versions
python cli.py schedule-add discovery 127.0.0.1 3600  # Part 4: scan hourly
python cli.py schedules                # list scan schedules
python cli.py changes                  # Part 5: scan-to-scan change log
python cli.py scans                    # list scan history
python cli.py scan 1                   # show a scan's host + port results
python cli.py assets                   # list discovered hosts
```

### API equivalents
Reading needs `monitoring:read`, scans and schedules `monitoring:run` (analyst / admin); log in first.
```bash
curl -b jar -X POST localhost:8000/monitoring/discover -H 'content-type: application/json' -d '{"target":"127.0.0.1"}'
curl -b jar localhost:8000/monitoring/scans
curl -b jar localhost:8000/monitoring/assets
```

## Vulnerability correlation (block 3)
Turns the software found by Monitoring version scans (plus software entered manually) into
**findings**: one per asset, CVE and product, with CVSS severity and the CISA KEV
"known exploited" flag. Code: `app/correlation/`. Backlog: E5 (S5.1–S5.4).

```
port_results (Nmap -sV) ─┐                        NVD CVE API 2.0 ─┐ (cached per product)
manual software ─────────┴─► cpe.py ─► vendor:product:version ─────┴─► engine.py ─► findings
                                         (unmapped products reported)    CISA KEV ─┘
```

| Step | How |
|------|-----|
| Software → asset | Latest completed **version** scan of the asset's IP. Interim rule until `S4.2`: the IP must belong to exactly one active asset (otherwise skipped with a warning) |
| Software → CPE (S5.1) | catalogue in `cpe.py` (OpenSSH, Apache httpd, nginx, IIS, Exim, vsftpd, MySQL, Samba, …); distribution suffixes (`Ubuntu 4ubuntu0.5`) are stripped for matching and kept for display; unknown products are listed as *unmapped*, never guessed. **No version, no finding:** software whose version was not detected is reported in the run warnings but never matched. Manual software may give `vendor:product` |
| CVEs (S5.2) | NVD per vendor/product, version ranges evaluated locally (`versionStart/End Including/Excluding`, `7.4p1`, `1.0.1g`, `rc` versions). Cached `CAG_NVD_CACHE_HOURS`; when NVD is unreachable the older cache is used. Rate limits respected with/without key; responses size-limited and validated |
| Platform (AND) configurations | e.g. "X running on Y": the platform cannot be checked, so the finding is created with `confidence = low` |
| KEV (S5.3) | catalogue cached in the database (works offline), refreshed by the periodic job or `POST /correlation/kev/refresh` |
| Lifecycle (S5.4) | `open` → `in_remediation` / `accepted_risk` (reason required) by analysts. A finding is closed (`resolved`, or `verified_fixed` if a `ticket_key` exists) **only on proof**: the same product on the same port now runs a known, non-affected version, checked against fresh CVE data. A port that went quiet, another product on the port, an unknown version, or stale/failed NVD data keep it open. If the vulnerable version returns it is reopened. Findings are never deleted |
| When | automatically after each version scan, every `CAG_CORRELATION_INTERVAL_HOURS`, or `POST /correlation/run` (returns `202` at once and runs in the background; `409` while another run is queued or running) |
| Concurrency | one run at a time per process; each asset row is locked while it is correlated (`SELECT … FOR UPDATE` on PostgreSQL); runs left `running` by a crash are marked `failed` at startup |

API (log in first; reading needs `findings:read`, changes `findings:write`):
```bash
curl -b jar -X POST localhost:8000/correlation/run                       # all active assets -> 202 + run id
curl -b jar localhost:8000/correlation/runs/1                            # follow the run
curl -b jar "localhost:8000/findings?severity=CRITICAL&status=open"     # also: kev=true, asset_id=, cve=
curl -b jar localhost:8000/assets/<asset-id>/findings
curl -b jar -X PATCH localhost:8000/findings/1 -H 'content-type: application/json'      -d '{"status":"accepted_risk","reason":"isolated lab system"}'
curl -b jar -X POST localhost:8000/assets/<asset-id>/software -H 'content-type: application/json'      -d '{"product":"OpenSSH","version":"8.2p1"}'                         # needs assets:write
curl -b jar localhost:8000/correlation/runs                              # history incl. unmapped software
```

Known limitations: upstream version matching flags distribution backports as vulnerable (`S5.6`);
no Alembic migration yet (tables are created on startup like the other modules, `S1.2`).
The opt-in live test queries the real NVD API: `CAG_LIVE_NVD=1 pytest -k live`.

## Jira tasks for security findings

CyberAsset Guard can create a **Jira Cloud task** for each qualifying security finding and
track it through remediation and verification:

```
Asset inventory -> network scan -> CVE correlation -> context -> Risk Engine
  -> qualification -> Jira task (label "finding") -> remediation -> re-scan -> verified fixed
```

The integration is **off by default**. With it off (or misconfigured), scans, correlation and
risk assessments work exactly as before.

### Prerequisites (Jira Cloud)
- A Jira Cloud site, here `https://example.atlassian.net`. Jira Server / Data Center is not
  supported (it uses another API version and authentication).
- An **existing** project. Its key is the prefix of its issue keys (e.g. `ASSET` in `ASSET-12`),
  shown in *Project settings -> Details*. No project is ever created.
- An Atlassian account (ideally a dedicated bot account) with the project permissions
  *Browse projects*, *Create issues* and *Add comments*.
- The issue type **Task** must exist in the project and its create screen must include the
  **Labels** field (*Project settings -> Issue types -> Task*). The integration checks this
  through Jira's create metadata before the first task; a missing project, issue type or Labels
  field is reported as an `invalid_project` error.
- An **API token** for that account: <https://id.atlassian.com/manage-profile/security/api-tokens>
  -> *Create API token*.

### Configuration
Set the variables in your local `.env` (git-ignored; never commit it) or in the deployment's
secret store - **never in code or in Git**:

```dotenv
CAG_JIRA_ENABLED=true
CAG_JIRA_BASE_URL=https://example.atlassian.net
CAG_JIRA_PROJECT_KEY=<YOUR_EXISTING_PROJECT_KEY>
CAG_JIRA_EMAIL=<YOUR_JIRA_ACCOUNT_EMAIL>
CAG_JIRA_API_TOKEN=<YOUR_JIRA_API_TOKEN>
```

| Variable | Default | Meaning |
|---|---|---|
| `CAG_JIRA_ENABLED` | `false` | Turn the integration on |
| `CAG_JIRA_BASE_URL` | - | Jira Cloud site; only `https://<site>.atlassian.net` is accepted |
| `CAG_JIRA_PROJECT_KEY` | - | Key of the existing project |
| `CAG_JIRA_EMAIL` / `CAG_JIRA_API_TOKEN` | - | Account e-mail and API token (HTTP Basic auth) |
| `CAG_JIRA_ISSUE_TYPE` | `Task` | Issue type of the created tasks |
| `CAG_JIRA_LABEL` | `finding` | Mandatory label on every task |
| `CAG_JIRA_AUTO_CREATE` | `true` | `false`: tasks only when an analyst requests one |
| `CAG_JIRA_MIN_SEVERITY` | `HIGH` | Lowest risk level that creates a task automatically |
| `CAG_JIRA_INCLUDE_LOW_CONFIDENCE` | `false` | Also auto-create tasks for potential (unconfirmed) findings |
| `CAG_JIRA_DEFAULT_ASSIGNEE` | - | Atlassian account id of the assignee (optional) |
| `CAG_JIRA_TIMEOUT_SECONDS` | `10` | Timeout per Jira request |
| `CAG_JIRA_MAX_RETRIES` | `3` | Retries after the first attempt for temporary errors |
| `CAG_JIRA_DELIVERY_INTERVAL_MINUTES` | `5` | How often the delivery worker runs |
| `CAG_PUBLIC_URL` | - | https URL of this instance, used for a link back in each task |

Restart the application after changing them. **Check the result** in the web UI under
*Assessments -> Jira tasks* or with `GET /integrations/jira`: `enabled`, `disabled`, or
`misconfigured` with the variable that is wrong (values, the token in particular, are never
shown). Disable the integration with `CAG_JIRA_ENABLED=false`; existing task links stay visible.

### Which findings get a task
The Risk Engine's level decides - there is no second scoring. Automatically, a task is created
for a finding that is **open or in remediation**, on an **active** asset, **risk-assessed**,
not linked to a ticket by hand, with a risk level **>= `CAG_JIRA_MIN_SEVERITY`** (default:
CRITICAL and HIGH; MEDIUM and LOW are excluded) and **high confidence**.

| Classification | Meaning | Automatic task |
|---|---|---|
| confirmed version match | the detected version is in the CVE's affected range | yes (if the level qualifies) |
| potential - requires validation | version unknown or platform-specific CVE | only with `CAG_JIRA_INCLUDE_LOW_CONFIDENCE=true` |
| resolved | fixed / verified fixed | never |

"Confirmed" means a version match, not a verified exploit; the task states the classification and
never upgrades it. Analysts and administrators (`findings:write`) can create a task by hand for
any open, assessed finding (button *Create Jira Task* on the Findings page) - the severity
threshold is then their decision; the other checks, the persistence and the duplicate prevention
are the same. The Findings page shows for every finding its task (link and last known Jira
status), *Pending*, *Retrying*, *Failed* (with the error) or *Not eligible* with the reason.

Every task carries: summary `[LEVEL] CVE-… in <software> <version> – <asset>`, labels `finding`
and `cyberasset-guard` plus an internal correlation label, the priority mapped from the risk level
(Critical -> Highest, High -> High, Medium -> Medium, Low -> Low - only if the project offers that
priority) and a description with *Security Finding* (id, classification, severity, risk score,
asset, detection time, CVE), *Technical Evidence*, *Context and Risk Explanation* (the Risk Engine
factors), *Recommended Remediation* and *Verification Criteria*. Only data that exists is used;
all values are inserted as plain text.

### Duplicate prevention and recurrence
- One delivery record per finding (`jira_tickets`, `UNIQUE(finding_id)`) is written to the
  database **before** Jira is called. Repeated scans and concurrent assessment runs find the
  existing record; a second insert fails on the constraint.
- A worker takes a record with an atomic conditional update (a lease), so two workers - also in
  different processes - never send the same record. A lease left by a crash expires after
  5 minutes and the record is picked up again.
- Each record has a random correlation label that is put on the task. **Before every create the
  worker searches Jira for that label** and adopts an issue it finds. A timeout or 5xx after Jira
  may already have created the task therefore never leads to a second task; a timeout is never
  taken to mean "not created". (Jira's search index can lag a few seconds; retries wait at least
  a minute.)
- **Recurrence:** one task per finding for its whole life. When a re-scan shows a fixed version,
  the finding becomes *verified fixed* and a comment is added to the task (the task is not
  closed automatically - close it through your workflow). If the vulnerable version comes back,
  the finding reopens and the **same task** gets a comment; no new task is created.

### Failures and retries
Ticket delivery is separate from detection: a Jira outage never fails a scan or an assessment
and never changes or removes a finding.

| Category | Examples | Handling |
|---|---|---|
| `timeout`, `network`, `server` (5xx), `rate_limited` (429), `malformed` | Jira slow or unreachable | retried with exponential backoff (1, 2, 4 … min, `Retry-After` honoured), at most `CAG_JIRA_MAX_RETRIES` times |
| `authentication` (401), `permission` (403), `invalid_project`, `invalid_request` (400), `config` | wrong token, missing permission, no Task type | **not retried** - state *Failed* until fixed |

After fixing the cause, an analyst clicks *Retry* (or `POST /findings/{id}/ticket`). Creation,
manual requests, retries and failures are written to the audit log (`jira.ticket_created`,
`jira.ticket_requested`, `jira.ticket_retry`, `jira.ticket_failed`) with the issue key or the
error category - never with credentials.

### Security
- The base URL must be `https://<site>.atlassian.net` (no path, port, credentials or query);
  redirects are never followed, so the credentials are sent to that host only.
- Timeouts on every request and a 1 MB limit on responses; responses are validated.
- The token is never logged, stored, returned by the API or written to the audit log; error
  messages contain the HTTP status and Jira's error text only.
- The settings come from the environment only - there is no API to change them. Reading ticket
  state needs `findings:read`; creating, retrying and syncing need `findings:write`.

### API
```
GET  /integrations/jira               # state, policy, task counts (findings:read)
GET  /findings/{id}/ticket            # the finding's task record (findings:read)
POST /findings/{id}/ticket            # create or retry (findings:write) -> 202
POST /findings/{id}/ticket/sync       # read the task's current Jira status (findings:write)
```
`GET /findings` and `GET /assets/{id}/findings` include `ticket` and `jira_eligibility` per finding.
Jira statuses are shown, not mapped onto finding statuses (inbound synchronisation is a later phase).

### Tests and a controlled end-to-end check
`tests/test_jira_tickets.py` runs against a **mocked Jira** (`FakeJira`) - no real requests, no
credentials needed: `python -m pytest tests/test_jira_tickets.py`. Passing mocked tests do **not**
prove connectivity to the real Jira site. For a controlled manual check:
1. Set the variables above in your local `.env`, pointing at the project (ideally a test project or
   with a test label) and start the app; *Assessments -> Jira tasks* must show *Enabled*.
2. Create a test asset with a CRITICAL/HIGH finding (e.g. a version scan of a lab host), or pick an
   existing finding and click *Create Jira Task*.
3. Check in Jira: a *Task* with label `finding`, the expected summary and description; in
   CyberAsset Guard the link and the audit event `jira.ticket_created`.
4. Run the assessment again: no second task. Delete the test task in Jira afterwards if needed.

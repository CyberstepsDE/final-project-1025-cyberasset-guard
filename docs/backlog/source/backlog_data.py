"""Single source of truth for the CyberAsset Guard backlog (generates BACKLOG.md and jira-import.csv).

Fields per item:
  id, type (Epic|Story|Task|Bug|Sub-task), parent, title, story (user story / objective),
  description, value, ac (list), deps (list of ids), priority, sp (estimate), security, testing,
  labels (list), category (remaining|tech-debt|future|review), phase
"""

EPICS = [
    dict(id="E1", title="Application Foundation and Infrastructure",
         description="Build, CI, schema migrations, code quality and dependency management for the "
                     "FastAPI/SQLAlchemy/SQLite application. Runtime config, health checks, logging, backup "
                     "and Docker exist on main; CI, migrations and quality tooling do not."),
    dict(id="E2", title="User and Access Management",
         description="Authentication, role-based access control and the audit log. Implemented on branch "
                     "feature/auth-rbac-audit (commit 453d973, not merged). Remaining: merge, hardening and "
                     "enhancements (API tokens, rate limiting, MFA, SSO, audit retention)."),
    dict(id="E3", title="Asset Inventory",
         description="Central inventory of IT assets (block 1). Core CRUD, search, filtering, lifecycle and web UI "
                     "are complete on main. Remaining items are improvements only."),
    dict(id="E4", title="Asset Monitoring",
         description="Network discovery, ports, services, versions, scheduled scans and change detection "
                     "(block 2). The Monitoring module exists on main but is not linked to managed assets, "
                     "has a target-validation security gap and no dedicated tests."),
    dict(id="E5", title="Vulnerability Management",
         description="Correlate identified software with CVE data (NVD, CISA KEV) and maintain asset-to-finding "
                     "relationships (block 3). Not implemented on main. An unreviewed prototype exists only on the "
                     "local branch feature/correlation-risk-action and may be used as reference."),
    dict(id="E6", title="Context-Aware Risk Engine",
         description="Explainable risk score combining CVSS, exposure, criticality, environment and "
                     "exploitability (block 4). Not implemented on main."),
    dict(id="E7", title="Remediation and Verification",
         description="Jira ticket creation, remediation status and re-scan verification (block 5), plus future "
                     "SIEM integration. Not implemented on main."),
    dict(id="E8", title="Security and Quality Assurance",
         description="Cross-cutting security reviews, automated security scanning and test gaps for existing "
                     "functionality (Monitoring module, browser UI)."),
    dict(id="E9", title="Deployment, Operations and Maintenance",
         description="Production-like deployment (TLS), scheduled backups, logging operations, releases and "
                     "repository hygiene. Local MVP deployment (Docker, health checks, manual backup) exists on main."),
]

ITEMS = [
    # ------------------------------------------------------------------ E1
    dict(id="S1.1", type="Task", parent="E1", priority="High", sp=3, phase=0, category="remaining",
         title="Set up CI pipeline for tests and Docker build",
         story="Technical objective: every push and pull request is tested automatically so that main stays releasable.",
         description="There is no CI configuration in the repository (no .github/workflows). Add a GitHub Actions "
                     "workflow that installs requirements-dev.txt with constraints.txt, runs pytest on Python 3.11 "
                     "(minimum supported) and 3.13, and runs the opt-in Docker deployment test "
                     "(CAG_TEST_DOCKER=1 pytest -k docker) on Linux.",
         value="Prevents regressions from reaching main; the documented Python minimum (3.11) is currently untested.",
         ac=["Workflow runs on push and on pull requests to main",
             "Test job runs on Python 3.11 and 3.13 and fails the build on any test failure",
             "Docker job builds the image and runs the Docker deployment test",
             "Branch protection on main requires the CI checks to pass (configured by a repo admin)",
             "README documents the CI and how to reproduce it locally"],
         deps=[], security="Pin third-party actions to commit SHAs; the pipeline needs no secrets; use least-privilege "
                           "GITHUB_TOKEN permissions (contents: read).",
         testing="Open a test PR with a deliberately failing test and verify the check blocks the merge.",
         labels=["ci", "infrastructure"]),
    dict(id="S1.2", type="Task", parent="E1", priority="High", sp=5, phase=1, category="tech-debt",
         title="Introduce Alembic schema migrations with a baseline of the current schema",
         story="Technical objective: schema changes (starting with Asset Monitoring) can be applied to existing "
               "databases without data loss.",
         description="Tables are created with SQLAlchemy create_all (asset_inventory, asset_tags, users, user_sessions, "
                     "audit_events) and raw CREATE TABLE IF NOT EXISTS (Monitoring tables). create_all cannot alter "
                     "existing tables. Add Alembic, create a baseline revision matching the current schema "
                     "(including the audit_events append-only triggers and CHECK constraints) and a documented "
                     "procedure to stamp existing databases.",
         value="Required before any column change to existing tables, e.g. linking monitoring hosts to assets (S4.2).",
         ac=["alembic upgrade head on an empty database produces a schema identical to the current create_all + "
             "init_db schema (verified by comparing sqlite_master)",
             "Existing databases can be stamped at the baseline without changes to data",
             "Application startup refuses to start (clear log message) or upgrades automatically when migrations "
             "are pending - behaviour decided and documented",
             "Backup is recommended/created before migrations in the documented procedure",
             "README section 'Database initialization and migrations' is updated"],
         deps=["S2.1"], security="Migrations must preserve the audit_events UPDATE/DELETE triggers.",
         testing="Automated test: upgrade from empty DB and from a copy of a pre-migration DB; data and triggers intact.",
         labels=["database", "tech-debt"]),
    dict(id="S1.3", type="Task", parent="E1", priority="Medium", sp=3, phase=1, category="tech-debt",
         title="Add linting, formatting and type checking",
         story="Technical objective: consistent code style and early detection of type errors.",
         description="No linter, formatter, type checker or pre-commit configuration exists. Add ruff (lint + format), "
                     "mypy for app/assets, app/auth, app/audit (Monitoring may start with relaxed settings), a "
                     "pre-commit configuration and .gitattributes enforcing LF line endings (current commits show "
                     "CRLF conversion warnings on Windows).",
         value="Lower review effort and fewer defects; consistent line endings across Windows and Linux contributors.",
         ac=["ruff and mypy run in CI (S1.1) and pass on main",
             ".pre-commit-config.yaml runs ruff and basic hygiene hooks",
             ".gitattributes normalises text files to LF",
             "README documents the developer workflow"],
         deps=["S1.1"], security="Enable ruff's flake8-bandit (S) rules as a first SAST layer.",
         testing="CI job fails on a deliberately introduced lint error.",
         labels=["code-quality", "tech-debt"]),
    dict(id="S1.4", type="Task", parent="E1", priority="Medium", sp=2, phase=1, category="remaining",
         title="Automate dependency updates and refresh constraints.txt",
         story="Technical objective: dependencies stay current and pinned versions are reproducible.",
         description="constraints.txt was generated on Windows with Python 3.13. Configure Dependabot (pip, Docker, "
                     "GitHub Actions) and document how constraints.txt is regenerated and verified on Linux.",
         value="Security patches reach the application quickly without unreviewed version drift.",
         ac=["Dependabot (or Renovate) opens PRs for pip, Dockerfile base image and actions",
             "Documented procedure regenerates constraints.txt and the CI run validates it",
             "Base image python:3.13-slim is updated through the same process"],
         deps=["S1.1"], security="Review changelogs of security-relevant packages (fastapi, starlette, sqlalchemy).",
         testing="CI must pass on every dependency PR before merge.",
         labels=["dependencies", "ci"]),
    dict(id="S1.5", type="Story", parent="E1", priority="Low", sp=8, phase=5, category="tech-debt",
         title="Migrate Monitoring persistence from raw sqlite3 to SQLAlchemy",
         story="Technical objective: one data-access layer, so Monitoring tables can use foreign keys, migrations and "
               "the shared session/transaction handling.",
         description="Asset Management, auth and audit use SQLAlchemy; Monitoring (app/db.py, app/monitoring/*) uses "
                     "sqlite3 with its own connection handling. Port the Monitoring tables to SQLAlchemy models "
                     "without changing the API contract.",
         value="Reduces duplicated infrastructure and makes cross-module transactions (scan + audit) possible.",
         ac=["Monitoring tables are SQLAlchemy models managed by Alembic",
             "All Monitoring API responses are unchanged (contract tests from S8.1 pass)",
             "No raw SQL string building remains in the Monitoring module"],
         deps=["S1.2", "S8.1"], security="Keep parameterised queries; no behavioural change to access control.",
         testing="S8.1 test suite passes unchanged before and after the migration.",
         labels=["tech-debt", "monitoring", "database"]),

    # ------------------------------------------------------------------ E2
    dict(id="S2.1", type="Story", parent="E2", priority="Highest", sp=3, phase=0, category="review",
         title="Review and merge login, RBAC and audit log (feature/auth-rbac-audit)",
         story="As an administrator, I want the implemented login, role-based access control and audit log on main, "
               "so that the application is no longer usable without authentication.",
         description="Implemented and tested locally on branch feature/auth-rbac-audit (commit 453d973): scrypt password "
                     "hashing, server-side sessions, lockout, roles viewer/analyst/admin, permission checks on all "
                     "asset/monitoring/user/audit endpoints, append-only audit log, CSRF origin check, security headers, "
                     "UI pages for login/users/audit. 154 tests pass locally (incl. Docker). The branch is not pushed "
                     "and has not been reviewed by a second developer.",
         value="Closes the largest current security gap on main (no authentication at all).",
         ac=["Branch pushed and pull request opened against main",
             "Code review by a second developer using the security review checklist (subtask)",
             "All tests pass in CI (S1.1) or, if CI is not ready yet, in a documented local run",
             "Upgrade note executed on every existing environment: first administrator created with "
             "python -m app.maintenance create-user <name> --role admin",
             "README security section reviewed and accurate"],
         deps=[], security="Breaking change: after the merge the API and UI require login. Verify cookie flags, "
                           "lockout, CSRF origin check and that no secrets reach logs or audit details.",
         testing="Existing tests (test_auth.py, test_audit.py, updated test_assets.py / test_infrastructure.py); "
                 "manual smoke test of login, roles and audit UI in a browser.",
         labels=["security", "auth", "review"]),
    dict(id="T2.1.1", type="Sub-task", parent="S2.1", priority="Highest", sp=None, phase=0, category="review",
         title="Security review checklist for auth/session/CSRF/audit code",
         story="", description="Review app/auth/*, app/audit/*, the middleware in app/main.py and the UI changes against "
                               "OWASP ASVS L1 session management and access control requirements.",
         value="", ac=["Checklist completed and attached to the PR", "Findings filed as bugs or fixed before merge"],
         deps=[], security="", testing="", labels=["security", "review"]),
    dict(id="T2.1.2", type="Sub-task", parent="S2.1", priority="High", sp=None, phase=0, category="review",
         title="Create first administrator on each environment after merge",
         story="", description="Run create-user (local) or docker compose exec ... create-user (Docker). Store the "
                               "initial password in the team password manager.",
         value="", ac=["Every environment has at least one active administrator", "No password is stored in Git, chat or tickets"],
         deps=[], security="", testing="", labels=["operations"]),
    dict(id="S2.2", type="Story", parent="E2", priority="High", sp=3, phase=1, category="remaining",
         title="Rate-limit login attempts per client IP",
         story="As a security administrator, I want login attempts limited per IP address, so that password spraying "
               "across many accounts is slowed down.",
         description="Only per-account lockout exists (CAG_LOGIN_MAX_FAILURES). An attacker can try one password "
                     "against many usernames without triggering a lockout. Add an IP-based limit for /auth/login.",
         value="Mitigates credential stuffing / password spraying.",
         ac=["More than N failed logins per IP within a window return HTTP 429 (N and window configurable)",
             "Successful logins are not blocked for other IPs",
             "Rate-limit hits are written to the audit log (action auth.rate_limited)",
             "Works behind a reverse proxy when proxy headers are trusted explicitly (documented)"],
         deps=["S2.1"], security="Do not trust X-Forwarded-For unless configured; avoid unbounded in-memory state.",
         testing="Automated tests for limit, window reset, audit entry and proxy-header handling.",
         labels=["security", "auth"]),
    dict(id="S2.3", type="Story", parent="E2", priority="High", sp=3, phase=1, category="remaining",
         title="Force password change after administrator-set passwords",
         story="As a user, I want to be required to choose my own password after an administrator created or reset it, "
               "so that only I know my password.",
         description="Administrators set initial passwords and reset passwords (POST /users, POST /users/{id}/password, "
                     "maintenance create-user/reset-password). Add a must_change_password flag that restricts the "
                     "session to the password-change endpoint until a new password is set.",
         value="Administrators no longer know users' long-term passwords.",
         ac=["Users created or reset by an admin/CLI must change their password at next login",
             "Until changed, all endpoints except /auth/me, /auth/password and /auth/logout return 403",
             "The UI redirects to the password-change page",
             "Self-service changes clear the flag; audit entries record the forced change"],
         deps=["S2.1", "S1.2"], security="Flag must be enforced server-side, not only in the UI.",
         testing="API tests for restricted session, flag clearing and audit; UI e2e test (S8.4).",
         labels=["security", "auth"]),
    dict(id="S2.4", type="Story", parent="E2", priority="Medium", sp=5, phase=2, category="remaining",
         title="Personal API tokens for automation",
         story="As an analyst, I want a personal API token, so that scripts can use the API without my password or a "
               "browser session.",
         description="The API currently only accepts the session cookie. Add personal tokens (Bearer) that inherit the "
                     "user's role, have an expiry, can be revoked and are shown once.",
         value="Enables integrations (CI, scripts, future SIEM export) without sharing passwords.",
         ac=["Users can create, list (without secret) and revoke their own tokens; admins can revoke any token",
             "Only a hash of the token is stored; the token is shown exactly once",
             "Tokens expire (max lifetime configurable) and stop working when the user is disabled",
             "Requests with a token are attributed to the user in the audit log (with token id)",
             "CSRF origin check is not required for token-authenticated requests and still applies to cookies"],
         deps=["S2.1", "S1.2"], security="Constant-time comparison, token prefix for secret scanning, never log tokens.",
         testing="API tests for lifecycle, expiry, revocation, RBAC parity with sessions and audit attribution.",
         labels=["auth", "api"]),
    dict(id="S2.5", type="Story", parent="E2", priority="Medium", sp=3, phase=2, category="remaining",
         title="View and revoke active sessions",
         story="As an administrator, I want to see and end active sessions, so that I can react to a lost device or "
               "a suspected account compromise.",
         description="Sessions are stored server-side (user_sessions) but there is no UI/API to list or revoke them "
                     "individually; today they end only via logout, expiry, password change, role change or disable.",
         value="Faster incident response without disabling the whole account.",
         ac=["Users see their own sessions (created, last seen, IP) and can end them",
             "Administrators can list and end sessions of any user",
             "Ending a session is audit-logged"],
         deps=["S2.1"], security="Never expose token hashes through the API.",
         testing="API + UI tests for listing and revocation.",
         labels=["auth"]),
    dict(id="S2.6", type="Story", parent="E2", priority="Medium", sp=5, phase=2, category="remaining",
         title="Audit log retention, export and archival",
         story="As a compliance officer, I want a defined retention period and an export of the audit log, so that "
               "personal data (usernames, IP addresses) is not kept longer than necessary and evidence can be archived.",
         description="audit_events is append-only via database triggers and grows without limit. Define a retention "
                     "period, an export (CSV/JSON) for administrators and a controlled archival/purge procedure that "
                     "works with the append-only triggers.",
         value="GDPR data minimisation and audit evidence for reviews.",
         ac=["Retention period documented with its justification",
             "Admins can export filtered audit events (CSV and JSON); exports are themselves audit-logged",
             "Maintenance command archives and purges events older than the retention period, leaving an audit "
             "record of the purge",
             "Normal API/application code still cannot update or delete audit events"],
         deps=["S2.1"], security="CSV export must neutralise formula injection; purge only through the maintenance "
                                 "command with explicit confirmation.",
         testing="Tests for export content/escaping, purge boundaries and trigger behaviour.",
         labels=["audit", "compliance"]),
    dict(id="S2.7", type="Story", parent="E2", priority="Medium", sp=8, phase=4, category="future",
         title="Multi-factor authentication (TOTP) for administrators",
         story="As an administrator, I want to protect my account with a second factor, so that a leaked password "
               "alone does not give access to user management and the audit log.",
         description="Future enhancement. TOTP enrolment, recovery codes, enforcement for the admin role.",
         value="Strong protection of the most privileged accounts.",
         ac=["Admins can enrol TOTP with a QR code and confirm with a code",
             "Login requires the TOTP code when enrolled; enforcement for admins configurable",
             "One-time recovery codes; reset by another admin is audit-logged"],
         deps=["S2.1"], security="Secrets encrypted at rest or stored with minimal exposure; replay protection.",
         testing="API and e2e tests for enrolment, login and recovery.",
         labels=["auth", "future"]),
    dict(id="S2.8", type="Story", parent="E2", priority="Low", sp=13, phase=5, category="future",
         title="Single sign-on via OIDC",
         story="As an organisation, I want users to sign in with our identity provider, so that accounts and "
               "offboarding are managed centrally.",
         description="Future enhancement. OIDC login with role mapping from IdP groups; local accounts remain for "
                     "break-glass administration.",
         value="Central identity lifecycle and MFA from the IdP.",
         ac=["OIDC authorization-code flow with PKCE", "Group-to-role mapping configurable",
             "Local admin login remains available as break-glass and is audit-logged"],
         deps=["S2.1"], security="Validate issuer, audience, nonce and state; no tokens in logs.",
         testing="Integration tests against a test IdP (e.g. Keycloak container).",
         labels=["auth", "future"]),

    # ------------------------------------------------------------------ E3
    dict(id="S3.1", type="Story", parent="E3", priority="Medium", sp=3, phase=2, category="remaining",
         title="Show asset change history to analysts on the asset detail page",
         story="As an analyst, I want to see who changed an asset and what changed, so that I can understand its "
               "current state without administrator rights.",
         description="Field-level diffs are recorded in the audit log (asset.*), but only administrators "
                     "(audit:read) can read them; the detail page links to the admin audit view. Add a read-only "
                     "history endpoint/section scoped to one asset's asset.* events for users with assets:read.",
         value="Traceability for the people who maintain the inventory.",
         ac=["GET /assets/{id}/history returns only asset.* events of that asset",
             "Visible to all roles with assets:read; IP addresses are not shown to non-admins",
             "Detail page shows a 'History' section with from -> to values"],
         deps=["S2.1"], security="Must not leak other event types (auth, user management) or IP addresses.",
         testing="API tests for scoping and field filtering per role; UI check.",
         labels=["assets", "audit"]),
    dict(id="S3.2", type="Story", parent="E3", priority="Medium", sp=5, phase=3, category="remaining",
         title="Bulk import and export of assets (CSV)",
         story="As an analyst, I want to import and export assets as CSV, so that I can onboard an existing "
               "inventory and share it with other tools.",
         description="Assets can only be created one by one (UI/API).",
         value="Fast onboarding of existing inventories (CMDB, spreadsheets).",
         ac=["Import validates every row with the same rules as POST /assets and imports nothing if any row is "
             "invalid (row-level error report)",
             "Import is limited in size and requires assets:write",
             "Export respects current filters and requires assets:read",
             "Each import is audit-logged with the number of created assets"],
         deps=["S2.1"], security="Neutralise CSV formula injection in exports; enforce upload size limits.",
         testing="Tests with valid, invalid, oversized and malicious CSV files.",
         labels=["assets"]),
    dict(id="S3.3", type="Story", parent="E3", priority="Low", sp=2, phase=3, category="remaining",
         title="Paginate the asset overview beyond 500 assets",
         story="As a user, I want to page through large inventories, so that no asset is hidden.",
         description="The UI loads at most 500 assets and shows a 'showing first 500' hint; the API already supports "
                     "limit/offset.",
         value="Usability for larger inventories.",
         ac=["UI pages through all results using limit/offset", "Total count stays visible", "Filters persist across pages"],
         deps=[], security="Keep the API limit cap (500).", testing="UI e2e test with > 500 assets (S8.4).",
         labels=["assets", "ui"]),
    dict(id="S3.4", type="Story", parent="E3", priority="Low", sp=5, phase=5, category="future",
         title="Link asset owners to user accounts or teams",
         story="As a security lead, I want asset ownership to reference real users or teams, so that remediation "
               "tickets can be assigned automatically.",
         description="Future enhancement. owner is free text today.",
         value="Prerequisite for automatic assignment in remediation (E7).",
         ac=["Owner can reference a user or team", "Existing free-text owners are migrated or kept as legacy text",
             "Deactivated users are flagged as invalid owners"],
         deps=["S2.1", "S1.2"], security="Respect RBAC when listing users for selection.",
         testing="Migration test with existing free-text owners.",
         labels=["assets", "future"]),

    # ------------------------------------------------------------------ E4
    dict(id="B4.1", type="Bug", parent="E4", priority="Highest", sp=2, phase=0, category="remaining",
         title="Scan targets are passed to nmap without validation (argument injection)",
         story="As a security administrator, I want scan targets validated before they reach nmap, so that a user "
               "cannot inject nmap options.",
         description="Verified in code: app/monitoring/scanner.py (lines 168-227) splits the user-supplied target on "
                     "whitespace and appends the parts to the nmap argument list. A target beginning with '-' (e.g. "
                     "'--script=...', '-iL /path', '-oN /path') is interpreted as an nmap option. Not exploited or "
                     "tested here (nmap is not installed in the review environment). Endpoints: POST "
                     "/monitoring/discover, /portscan, /versionscan, /schedules; after S2.1 only analysts/admins can "
                     "call them, on current main anyone can.",
         value="Prevents reading/writing server files or running nmap scripts through the API.",
         ac=["Each target token must be a valid IPv4/IPv6 address, CIDR, nmap octet range or hostname; anything "
             "else returns 422 with a clear message",
             "Tokens starting with '-' are always rejected",
             "Port specs are validated against an allow-list pattern",
             "Same validation applies to stored schedules (existing invalid schedules are disabled with a log entry)"],
         deps=[], security="Treat as a security bug; fix before exposing the Monitoring API to any network.",
         testing="Unit tests with malicious targets (option injection, shell metacharacters, very long input); "
                 "tests assert nmap is never invoked for rejected input.",
         labels=["security", "monitoring", "bug"]),
    dict(id="B4.2", type="Bug", parent="E4", priority="Medium", sp=1, phase=1, category="remaining",
         title="Scan schedules accept 1-second intervals and list endpoints have no upper limit",
         story="As an operator, I want sane limits on scan schedules and list sizes, so that the scanner and database "
               "cannot be overloaded by mistake.",
         description="Verified in code: ScheduleRequest.interval_seconds only requires >= 1; /monitoring/scans and "
                     "/monitoring/changes accept any 'limit' value.",
         value="Protects the host, the database and scanned networks.",
         ac=["Minimum schedule interval configurable (default e.g. 15 minutes)",
             "limit parameters capped (e.g. 500) and validated",
             "Concurrent scans limited"],
         deps=["B4.1"], security="Availability (DoS) protection.", testing="Validation tests for boundaries.",
         labels=["monitoring", "bug"]),
    dict(id="S4.1", type="Story", parent="E4", priority="Highest", sp=3, phase=0, category="remaining",
         title="Restrict scans to authorised network ranges",
         story="As a security administrator, I want scans limited to approved network ranges, so that the tool "
               "cannot be used to scan third-party systems.",
         description="Any target accepted by nmap can be scanned today. Add a configurable allow-list "
                     "(CAG_SCAN_ALLOWED_NETWORKS, default private ranges) checked after DNS resolution.",
         value="Legal and ethical safety: scanning without authorisation can be illegal.",
         ac=["Targets outside the allow-list are rejected with 403 and audit-logged",
             "Hostnames are resolved and every resolved address must be inside the allow-list",
             "CIDR/range targets must lie completely inside the allow-list",
             "Default and override documented"],
         deps=["B4.1"], security="Resolve DNS once and pass the resolved addresses to nmap to avoid DNS rebinding.",
         testing="Unit tests for inside/outside/partially-overlapping ranges and hostnames.",
         labels=["security", "monitoring"]),
    dict(id="S4.2", type="Story", parent="E4", priority="High", sp=8, phase=2, category="remaining",
         title="Link discovered hosts to managed assets",
         story="As an analyst, I want hosts found by scans matched to inventory assets, so that monitoring results "
               "belong to the right asset.",
         description="The Monitoring 'assets' table (hosts keyed by IP) and asset_inventory (UUID) are separate; no code "
                     "connects them. Add a link from discovered hosts to asset_inventory.id with automatic matching "
                     "by IP/hostname and manual confirmation; unmatched hosts become 'discovered, unmanaged' "
                     "candidates that an analyst can turn into assets.",
         value="Core of block 2: monitoring data in asset context.",
         ac=["Scan results of a host with a matching active asset are linked automatically (rule documented)",
             "Ambiguous matches are not linked automatically and are shown for manual decision",
             "Unmatched hosts are listed and can be converted into an asset (prefilled form)",
             "IP changes of an asset do not break existing links (link is by asset id)",
             "Linking/unlinking is audit-logged"],
         deps=["S1.2", "S2.1", "B4.1"], security="Only assets:write may link or create assets from candidates.",
         testing="Tests for exact, ambiguous and no match; IP change; inactive assets.",
         labels=["monitoring", "assets"]),
    dict(id="T4.2.1", type="Sub-task", parent="S4.2", priority="High", sp=None, phase=2, category="remaining",
         title="Alembic migration: link column/table between monitoring hosts and asset_inventory",
         story="", description="Add the foreign key with ON DELETE behaviour that never deletes scan history.",
         value="", ac=["Migration up/down tested on a copy of real data"], deps=[], security="", testing="",
         labels=["database"]),
    dict(id="T4.2.2", type="Sub-task", parent="S4.2", priority="High", sp=None, phase=2, category="remaining",
         title="Matching service and candidate list API",
         story="", description="Match by IP and hostname; expose GET /monitoring/candidates and POST link/unlink endpoints.",
         value="", ac=["Endpoints documented in OpenAPI and permission-checked"], deps=[], security="", testing="",
         labels=["monitoring"]),
    dict(id="T4.2.3", type="Sub-task", parent="S4.2", priority="Medium", sp=None, phase=2, category="remaining",
         title="UI: candidate hosts view and 'create asset from host'",
         story="", description="New page listing unmatched hosts with action to create or link an asset.",
         value="", ac=["Hidden for viewers; actions require assets:write"], deps=[], security="", testing="",
         labels=["ui"]),
    dict(id="S4.3", type="Story", parent="E4", priority="High", sp=5, phase=2, category="remaining",
         title="Show monitoring results on the asset detail page",
         story="As an analyst, I want to see reachability, open ports, services, versions and recent changes on an "
               "asset's page, so that I understand its exposure at a glance.",
         description="The detail page is prepared for additional sections (DETAIL_SECTIONS in app/web/static/app.js) "
                     "but shows no monitoring data.",
         value="Makes block 2 usable in the UI.",
         ac=["Section shows last scan time, reachability, open ports with service/product/version",
             "Recent changes (port opened/closed, version change) listed",
             "Clear 'not scanned yet' state; no fabricated data"],
         deps=["S4.2"], security="Escape all scanner-derived strings (banners are attacker-controlled).",
         testing="API tests; UI e2e test with seeded scan data (S8.4).",
         labels=["monitoring", "ui"]),
    dict(id="S4.4", type="Story", parent="E4", priority="Medium", sp=5, phase=2, category="remaining",
         title="Scan an asset on demand and schedule recurring scans from the UI",
         story="As an analyst, I want to start or schedule a scan for an asset from its page, so that I do not need "
               "the CLI or raw API.",
         description="Scans and schedules exist only as API/CLI operations on raw targets.",
         value="Self-service monitoring for analysts.",
         ac=["'Scan now' (discovery/port/version) on the asset page for monitoring:run",
             "Schedules can be created/removed per asset with the minimum interval from B4.2",
             "Scan status and errors (e.g. nmap missing) shown clearly",
             "Actions audit-logged (already done by middleware; verify)"],
         deps=["S4.2", "S4.1", "B4.2"], security="Targets taken from the asset, still validated by B4.1/S4.1.",
         testing="API + e2e tests with a fake scanner.",
         labels=["monitoring", "ui"]),
    dict(id="T4.5", type="Task", parent="E4", priority="Medium", sp=2, phase=2, category="remaining",
         title="Include nmap in the Docker image",
         story="Technical objective: Monitoring works in the containerised deployment.",
         description="The Dockerfile deliberately omits nmap (scans fail with 'nmap binary not found'). Install nmap, "
                     "keep the non-root user (TCP connect scans -sT work without root) and document limits "
                     "(no SYN/OS detection without extra capabilities).",
         value="Monitoring available in the documented deployment.",
         ac=["Image contains nmap; container still runs as uid 10001",
             "Docker test runs a version scan against a test service in the compose network",
             "Image size and added CVEs reviewed (S8.2 image scan)"],
         deps=["B4.1", "S4.1"], security="Do not add NET_RAW/NET_ADMIN capabilities by default.",
         testing="Extend the Docker deployment test.",
         labels=["docker", "monitoring"]),
    dict(id="S4.6", type="Story", parent="E4", priority="Low", sp=5, phase=5, category="future",
         title="Notify on relevant monitoring changes",
         story="As an analyst, I want to be notified when a new port opens or a service version changes on a critical "
               "asset, so that I can react quickly.",
         description="Future enhancement. Change detection exists (changes table) but nobody is notified.",
         value="Faster reaction to exposure changes.",
         ac=["Rules by asset criticality / change type", "Notification channel configurable (e-mail or webhook)",
             "Notifications audit-logged; no secrets in payloads"],
         deps=["S4.2"], security="Webhook URLs validated; outbound allow-list.", testing="Tests with a fake channel.",
         labels=["monitoring", "future"]),

    # ------------------------------------------------------------------ E5
    dict(id="S5.1", type="Story", parent="E5", priority="High", sp=5, phase=3, category="remaining",
         title="Normalise detected and manual software to CPE identifiers",
         story="As the vulnerability engine, I want software identified as CPE vendor/product/version, so that it can "
               "be matched against NVD data.",
         description="Nmap product/version strings (e.g. 'OpenSSH 8.2p1 Ubuntu 4ubuntu0.5') must be mapped to CPE "
                     "(openbsd:openssh:8.2p1). Include manual software entries for assets. A mapping catalogue and "
                     "version parser exist in the unreviewed prototype branch feature/correlation-risk-action "
                     "(reference only).",
         value="Prerequisite for any CVE correlation.",
         ac=["Catalogue maps common products (OpenSSH, Apache httpd, nginx, IIS, Exim, vsftpd, ...) and nmap CPE output",
             "Distribution suffixes are stripped and kept for display",
             "Unknown products are reported as 'unmapped' instead of guessed",
             "Manual software can be added to an asset (assets:write, audit-logged)"],
         deps=["S4.2"], security="Treat banners as untrusted input.",
         testing="Table-driven tests for mapping and version comparison (e.g. 8.2p1 < 9.3p2, 2.4.49 vs 2.4.50).",
         labels=["vulnerability"]),
    dict(id="S5.2", type="Story", parent="E5", priority="High", sp=8, phase=3, category="remaining",
         title="Retrieve CVE data from the NVD API with caching",
         story="As the vulnerability engine, I want CVEs for each product from the NVD API with version ranges, so "
               "that affected assets can be identified.",
         description="Query NVD CVE API 2.0 per vendor/product, evaluate version ranges locally, cache responses, respect "
                     "rate limits, optional API key, offline seed data for tests and air-gapped use.",
         value="Authoritative vulnerability data.",
         ac=["Version ranges (start/end including/excluding) evaluated correctly",
             "Platform-specific (AND) configurations handled or explicitly excluded with documentation",
             "Responses cached (configurable lifetime); stale cache used when NVD is unreachable",
             "Rate limits respected with and without API key",
             "NVD API key read from environment, never logged"],
         deps=["S5.1"], security="Outbound HTTPS only to the NVD host; validate and size-limit responses.",
         testing="Tests with recorded NVD fixtures; one opt-in live test.",
         labels=["vulnerability", "integration"]),
    dict(id="S5.3", type="Story", parent="E5", priority="Medium", sp=2, phase=3, category="remaining",
         title="Flag actively exploited CVEs using the CISA KEV catalogue",
         story="As an analyst, I want to know which CVEs are actively exploited, so that I fix those first.",
         description="Download and cache the CISA Known Exploited Vulnerabilities feed.",
         value="Key input for prioritisation and the risk engine.",
         ac=["KEV feed cached and refreshed daily", "Findings show a KEV flag", "Works offline with the last cached copy"],
         deps=["S5.2"], security="Validate feed format.", testing="Fixture-based tests.",
         labels=["vulnerability", "integration"]),
    dict(id="S5.4", type="Story", parent="E5", priority="High", sp=8, phase=3, category="remaining",
         title="Findings: asset-to-CVE relationship with lifecycle",
         story="As an analyst, I want each affected asset/CVE pair stored as a finding with a status, so that I can "
               "track it until it is fixed.",
         description="Persist findings (asset id, CVE, software, version, port, source) with statuses open, "
                     "in_remediation, resolved, verified_fixed, accepted_risk; re-correlate after scans and context changes.",
         value="Persistent vulnerability tracking per asset.",
         ac=["Correlation creates, updates and closes findings idempotently",
             "Findings that disappear after a re-scan are closed (verified_fixed if a ticket existed)",
             "A returning vulnerable version reopens the finding",
             "Risk acceptance requires a reason and is audit-logged",
             "Findings are never hard-deleted"],
         deps=["S5.2", "S1.2"], security="Status changes require appropriate permissions (new permission findings:write).",
         testing="Lifecycle tests: new, unchanged, fixed, regression, accepted.",
         labels=["vulnerability"]),
    dict(id="T5.4.1", type="Sub-task", parent="S5.4", priority="High", sp=None, phase=3, category="remaining",
         title="Data model and migration for findings", story="",
         description="SQLAlchemy model + Alembic migration, unique (asset, CVE, product).",
         value="", ac=["Migration tested up and down"], deps=[], security="", testing="", labels=["database"]),
    dict(id="T5.4.2", type="Sub-task", parent="S5.4", priority="High", sp=None, phase=3, category="remaining",
         title="New permissions findings:read / findings:write in the RBAC matrix", story="",
         description="Extend app/auth/permissions.py and tests in test_auth.py.",
         value="", ac=["Matrix test covers the new permissions"], deps=[], security="", testing="", labels=["auth"]),
    dict(id="S5.5", type="Story", parent="E5", priority="Medium", sp=5, phase=3, category="remaining",
         title="Findings list and asset findings section in the UI",
         story="As an analyst, I want to browse findings across assets and per asset, so that I can work through them.",
         description="List with filters (severity, KEV, status, asset) and a findings section on the asset page.",
         value="Makes block 3 usable.",
         ac=["Global findings list with filters and paging", "Asset page shows its findings",
             "Links to NVD for each CVE", "Viewer read-only"],
         deps=["S5.4"], security="Escape CVE descriptions and banners.", testing="UI e2e tests (S8.4).",
         labels=["vulnerability", "ui"]),
    dict(id="S5.6", type="Story", parent="E5", priority="Low", sp=8, phase=5, category="future",
         title="Reduce false positives from distribution backports",
         story="As an analyst, I want distribution-patched packages recognised, so that I do not chase CVEs that are "
               "already fixed (e.g. Ubuntu OpenSSH 8.2p1-4ubuntu0.x).",
         description="Future enhancement. Upstream-version matching flags backported fixes as vulnerable.",
         value="Trust in the findings list.", ac=["Approach evaluated (OS advisories / OVAL)", "Decision documented"],
         deps=["S5.4"], security="", testing="Fixture-based tests for known backports.", labels=["vulnerability", "future"]),

    # ------------------------------------------------------------------ E6
    dict(id="S6.1", type="Story", parent="E6", priority="High", sp=5, phase=4, category="remaining",
         title="Explainable contextual risk score per finding",
         story="As an analyst, I want each finding scored 0-100 from CVSS, internet exposure, asset criticality, "
               "environment and exploitability with an explanation, so that I fix the riskiest issues first.",
         description="Implements block 4. Must use the actual asset fields: internet_facing yes/no/unknown, "
                     "criticality low..critical, environment development..production. Define how 'unknown' exposure "
                     "is scored.",
         value="Prioritisation by real risk instead of CVSS alone.",
         ac=["Score and level (Low/Medium/High/Critical) computed per finding",
             "Per-factor points and a human-readable 'WHY' stored with the finding",
             "Scoring model documented and exposed read-only via the API",
             "Design example reproduces: CVSS 9.8, internet-facing, critical production asset, public exploit -> "
             "Critical (exact value per agreed weights)"],
         deps=["S5.4", "S5.3", "T6.4"], security="", testing="Table-driven unit tests for each factor and level boundary.",
         labels=["risk"]),
    dict(id="T6.4", type="Task", parent="E6", priority="High", sp=2, phase=4, category="remaining",
         title="Agree on risk model weights with stakeholders",
         story="Technical objective: the scoring weights are a documented, agreed decision.",
         description="Workshop with security stakeholders on factor weights, level thresholds and treatment of "
                     "'unknown' values.",
         value="Avoids rework and builds trust in scores.",
         ac=["Weights and thresholds documented", "Sign-off recorded in the ticket"],
         deps=[], security="", testing="", labels=["risk", "decision"]),
    dict(id="S6.2", type="Story", parent="E6", priority="Medium", sp=3, phase=4, category="remaining",
         title="Recalculate risk when asset context or threat data changes",
         story="As an analyst, I want risk scores to update when an asset's criticality, environment or exposure "
               "changes or a CVE becomes KEV-listed, so that priorities stay correct.",
         description="Trigger re-scoring on asset updates (asset.update) and intel refresh.",
         value="Scores never go stale.",
         ac=["Changing criticality/environment/internet_facing re-scores that asset's findings in the same request",
             "KEV refresh re-scores affected findings", "Risk history per asset stored"],
         deps=["S6.1"], security="", testing="Tests for each trigger.", labels=["risk"]),
    dict(id="S6.3", type="Story", parent="E6", priority="Medium", sp=5, phase=4, category="remaining",
         title="Risk overview: prioritised findings and riskiest assets",
         story="As a security lead, I want a prioritised view of findings and assets by risk, so that I can plan "
               "remediation work.",
         description="Overview page (no complex analytics): top findings, counts by level, riskiest assets.",
         value="Decision support for remediation planning.",
         ac=["Findings sorted by risk with WHY visible", "Counts per level", "Filter by environment/owner"],
         deps=["S6.1"], security="", testing="UI e2e test.", labels=["risk", "ui"]),

    # ------------------------------------------------------------------ E7
    dict(id="S7.1", type="Story", parent="E7", priority="High", sp=8, phase=5, category="remaining",
         title="Create Jira remediation tickets from findings",
         story="As an analyst, I want to create a Jira ticket from a finding with risk, explanation and remediation "
               "steps, so that the owner can fix it in their normal workflow.",
         description="Jira Cloud REST v3 integration configured via environment (URL, user, API token, project, issue "
                     "type). Idempotent per finding; priority mapped from risk level; simulated mode when not configured.",
         value="Closes the loop from detection to action (block 5).",
         ac=["Ticket contains CVE, asset, risk score, WHY and remediation steps",
             "Creating twice returns the existing ticket",
             "Priority mapping configurable; missing fields on the Jira screen handled gracefully",
             "Ticket key/link stored on the finding; action audit-logged"],
         deps=["S5.4", "S6.1"], security="API token only from environment/secret store; never in DB, logs, audit or "
                                         "UI; outbound host allow-list.",
         testing="Tests against a mocked Jira API; one opt-in test against a Jira sandbox.",
         labels=["remediation", "integration"]),
    dict(id="S7.2", type="Story", parent="E7", priority="High", sp=5, phase=5, category="remaining",
         title="Re-scan and verify risk reduction",
         story="As an analyst, I want to re-scan an asset after patching and see the risk before and after, so that "
               "the fix is verified.",
         description="Trigger a version scan for the asset, re-correlate and show closed findings and the risk delta.",
         value="Evidence that remediation worked.",
         ac=["One action triggers scan + correlation for the asset",
             "Result shows risk before/after and closed findings",
             "Findings closed this way become verified_fixed"],
         deps=["S4.4", "S5.4", "S6.1"], security="", testing="Tests with a fake scanner returning a patched version.",
         labels=["remediation"]),
    dict(id="S7.3", type="Story", parent="E7", priority="Medium", sp=5, phase=5, category="remaining",
         title="Synchronise remediation status from Jira",
         story="As an analyst, I want finding status to reflect the Jira ticket status, so that I do not update two "
               "systems.",
         description="Poll or webhook-based sync of ticket status into the finding (in_remediation, done).",
         value="Single source of truth for remediation progress.",
         ac=["Status mapping configurable", "Sync failures visible and retried",
             "'Done' in Jira does not close the finding until verified by re-scan"],
         deps=["S7.1"], security="Webhook requests authenticated (shared secret/signature).",
         testing="Tests with mocked Jira responses/webhooks.", labels=["remediation", "integration"]),
    dict(id="S7.4", type="Story", parent="E7", priority="Low", sp=8, phase=5, category="future",
         title="Forward audit events and findings to Splunk/SIEM",
         story="As a SOC analyst, I want CyberAsset Guard events in our SIEM, so that I can correlate them with "
               "other security events.",
         description="Future enhancement from the design ('Future: Splunk / SIEM / EDR'). HEC or syslog forwarding.",
         value="Integration into central security monitoring.",
         ac=["Configurable forwarding of audit events and finding changes", "Delivery retries and back-pressure",
             "No secrets or passwords in forwarded events"],
         deps=["S2.1", "S5.4"], security="TLS to SIEM; token from environment.", testing="Tests with a fake HEC endpoint.",
         labels=["integration", "future"]),

    # ------------------------------------------------------------------ E8
    dict(id="S8.1", type="Task", parent="E8", priority="High", sp=5, phase=1, category="remaining",
         title="Automated tests for the Monitoring module",
         story="Technical objective: the existing Monitoring code (scanner, diff, scheduler, routes) is covered by "
               "automated tests before it is extended.",
         description="Verified gap: no test file targets app/monitoring; it is only touched by a smoke test "
                     "(test_monitoring_module_still_available) and by auth/audit tests that replace the scanner with a "
                     "fake. Untested: nmap XML parsing, change detection (diff.py), scheduler persistence, error paths.",
         value="Safe refactoring for E4 and S1.5.",
         ac=["Nmap XML parsing tested with recorded fixtures (up/down hosts, open/filtered ports, -sV output)",
             "Change detection tested for every change type (host_up/down/new/gone, port_open/closed, "
             "service_change, version_change)",
             "Scheduler add/remove/restart persistence tested without real timing",
             "Error paths: nmap missing, timeout, non-zero exit, invalid XML",
             "No real network scans in the test suite"],
         deps=[], security="Include malicious XML/banner content in fixtures.",
         testing="This task is the testing work; target >= 85% line coverage for app/monitoring.",
         labels=["testing", "monitoring"]),
    dict(id="S8.2", type="Task", parent="E8", priority="High", sp=3, phase=1, category="remaining",
         title="Static analysis, dependency and container vulnerability scanning in CI",
         story="Technical objective: known vulnerable dependencies and insecure code patterns are detected automatically.",
         description="Add bandit (or ruff S rules), pip-audit for Python dependencies and Trivy for the Docker image "
                     "to CI.",
         value="Early detection of vulnerable dependencies in a security product.",
         ac=["pip-audit and an image scan run on every PR and weekly on main",
             "High/critical findings fail the build unless explicitly waived with a reason",
             "Results available as CI artefacts"],
         deps=["S1.1"], security="Waivers time-limited and reviewed.", testing="Introduce a known-vulnerable pin in a test "
                                                                                "branch to verify detection.",
         labels=["security", "ci"]),
    dict(id="S8.3", type="Task", parent="E8", priority="High", sp=5, phase=1, category="remaining",
         title="Threat model and independent security review",
         story="Technical objective: security risks of the current architecture are identified and tracked.",
         description="STRIDE threat model covering web UI, API, sessions, audit log, Monitoring/nmap execution, SQLite "
                     "file, backups and Docker deployment. Review by someone other than the implementer.",
         value="Systematic coverage instead of ad-hoc findings.",
         ac=["Data-flow diagram and threat list committed to docs/",
             "Each threat has a mitigation or a backlog item",
             "Review findings filed as bugs"],
         deps=["S2.1"], security="Covers B4.1-type issues systematically.", testing="",
         labels=["security"]),
    dict(id="S8.4", type="Task", parent="E8", priority="Medium", sp=5, phase=2, category="remaining",
         title="End-to-end browser tests for the web UI",
         story="Technical objective: UI flows are tested automatically, not only manually.",
         description="Verified gap: the UI (app/web) is only checked manually; pytest covers the API and that static "
                     "files are served. Add Playwright tests for login/logout, role-dependent visibility, asset "
                     "create/edit/deactivate, validation messages, search/filter, users page and audit page.",
         value="Prevents UI regressions as new modules add sections.",
         ac=["Playwright suite runs headless in CI against a temporary database",
             "Covers viewer, analyst and admin flows",
             "Checks that no console errors occur on the main pages"],
         deps=["S1.1", "S2.1"], security="Include XSS checks with malicious asset names/descriptions.",
         testing="This task is the testing work.", labels=["testing", "ui"]),
    dict(id="S8.5", type="Task", parent="E8", priority="Low", sp=3, phase=3, category="remaining",
         title="Accessibility review of the web UI (WCAG 2.1 AA basics)",
         story="Technical objective: the UI is usable with keyboard and screen readers.",
         description="Check labels, focus order, contrast in light/dark mode, dialogs and error announcements.",
         value="Usability for all users; fewer UI defects.",
         ac=["Automated axe checks in the e2e suite (S8.4) with no serious violations",
             "Keyboard-only walkthrough of main flows documented"],
         deps=["S8.4"], security="", testing="axe-core in Playwright.", labels=["ui", "testing"]),
    dict(id="S8.6", type="Task", parent="E8", priority="Low", sp=3, phase=3, category="remaining",
         title="Concurrency test: scheduler scans and API writes on SQLite",
         story="Technical objective: verify SQLite locking behaviour under concurrent scans and requests.",
         description="The app uses one SQLite file for scheduler threads and requests (busy_timeout 5 s). Behaviour "
                     "under load is untested.",
         value="Confidence in the single-instance SQLite design.",
         ac=["Test runs parallel API writes and scheduled scans (fake scanner) without 'database is locked' errors",
             "Documented limits (requests/s) for the MVP"],
         deps=["S8.1"], security="", testing="Load test script in tests/ (opt-in).", labels=["testing", "database"]),

    # ------------------------------------------------------------------ E9
    dict(id="S9.1", type="Story", parent="E9", priority="High", sp=3, phase=1, category="remaining",
         title="TLS reverse-proxy deployment profile",
         story="As an operator, I want a documented HTTPS deployment, so that credentials and session cookies are "
               "never sent in clear text.",
         description="The app serves plain HTTP and binds Docker to 127.0.0.1. Provide a compose profile with a reverse "
                     "proxy (e.g. Caddy) terminating TLS, CAG_COOKIE_SECURE=true, CAG_TRUSTED_ORIGINS and HSTS.",
         value="Required before any network exposure of the login.",
         ac=["Compose profile starts proxy + app; app port not published directly",
             "Session cookie has the Secure flag; HSTS header set",
             "Origin check works with the public URL",
             "Documented certificate options (internal CA / Let's Encrypt)"],
         deps=["S2.1"], security="TLS 1.2+ only; proxy headers trusted only from the proxy.",
         testing="Docker test variant verifying HTTPS login and cookie flags.",
         labels=["deployment", "security"]),
    dict(id="S9.2", type="Story", parent="E9", priority="Medium", sp=5, phase=2, category="remaining",
         title="Scheduled backups with retention and restore drill",
         story="As an operator, I want automatic, verified backups with a retention policy, so that data can be "
               "restored after a failure without manual steps being forgotten.",
         description="Backups (python -m app.maintenance backup) are manual and kept forever in CAG_BACKUP_DIR.",
         value="Reliable recovery.",
         ac=["Backups run on a schedule (documented for host cron and Docker)",
             "Retention policy (e.g. 7 daily, 4 weekly) enforced",
             "Optional off-host copy documented",
             "Quarterly restore drill procedure documented and tested once"],
         deps=[], security="Backups contain password hashes and audit data: restrict file permissions; consider encryption.",
         testing="Tests for retention logic; Docker test for scheduled backup.",
         labels=["operations", "backup"]),
    dict(id="T9.3", type="Task", parent="E9", priority="Low", sp=2, phase=3, category="remaining",
         title="Structured JSON logging option and log rotation guidance",
         story="Technical objective: logs can be shipped to central logging.",
         description="Logs are plain text on stderr.",
         value="Easier operations and SIEM onboarding.",
         ac=["CAG_LOG_FORMAT=json emits one JSON object per line", "Docker log rotation documented"],
         deps=[], security="No secrets/request bodies in logs (existing rule).", testing="Unit test for formatter.",
         labels=["operations", "logging"]),
    dict(id="T9.4", type="Task", parent="E9", priority="Low", sp=2, phase=3, category="remaining",
         title="Release process: versioning, changelog and image tags",
         story="Technical objective: reproducible, identifiable releases.",
         description="Version is hard-coded in app/__init__.py; no tags or changelog.",
         value="Traceability of deployed versions.",
         ac=["SemVer tags; CHANGELOG.md", "Docker images tagged with the version", "Release checklist documented"],
         deps=["S1.1"], security="", testing="", labels=["operations"]),
    dict(id="T9.5", type="Task", parent="E9", priority="Low", sp=1, phase=0, category="tech-debt",
         title="Repository hygiene: clean up merged and parked branches",
         story="Technical objective: contributors know which branch is current.",
         description="Remote branches monitoring-part1..5 and asset-management are fully merged into main. Local-only "
                     "branches (asset-management-draft-v1, feature/correlation-risk-action) exist on one machine. "
                     "Decide with the team what to delete or archive.",
         value="Less confusion; main is the single integration branch.",
         ac=["Team decision recorded", "Merged remote branches deleted or tagged",
             "Parked prototype either pushed as clearly-labelled reference or discarded"],
         deps=[], security="", testing="", labels=["repository"]),
]

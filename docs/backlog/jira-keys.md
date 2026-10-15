# Jira keys (project ASSET, example.atlassian.net)

Created 2026-10-13 via the Jira REST API in the logged-in browser session. All new issues carry the labels `cyberasset-guard` and `backlog-<ref>`; status `New`; dependencies as 'is blocked by' links (54).

Not created (already covered by existing issues, see BACKLOG.md): S5.1→ASSET-17, S5.2→ASSET-15, S5.3→ASSET-20, S5.4→ASSET-21, T5.4.1 (part of ASSET-16/21). Epics E3/E5 reuse ASSET-5 / ASSET-9. Bugs B4.1/B4.2 are Tasks with label `bug` (no Bug type in the project). T8.7 is new.

| Ref | Jira | Title |
|---|---|---|
| E1 | [ASSET-37](https://example.atlassian.net/browse/ASSET-37) | Application Foundation and Infrastructure |
| E2 | [ASSET-38](https://example.atlassian.net/browse/ASSET-38) | User and Access Management |
| E3 | [ASSET-5](https://example.atlassian.net/browse/ASSET-5) (existing) | Asset Inventory |
| E4 | [ASSET-39](https://example.atlassian.net/browse/ASSET-39) | Asset Monitoring |
| E5 | [ASSET-9](https://example.atlassian.net/browse/ASSET-9) (existing) | Vulnerability Management |
| E6 | [ASSET-40](https://example.atlassian.net/browse/ASSET-40) | Context-Aware Risk Engine |
| E7 | [ASSET-41](https://example.atlassian.net/browse/ASSET-41) | Remediation and Verification |
| E8 | [ASSET-42](https://example.atlassian.net/browse/ASSET-42) | Security and Quality Assurance |
| E9 | [ASSET-43](https://example.atlassian.net/browse/ASSET-43) | Deployment, Operations and Maintenance |
| S1.1 | [ASSET-44](https://example.atlassian.net/browse/ASSET-44) | Set up CI pipeline for tests and Docker build |
| S1.2 | [ASSET-45](https://example.atlassian.net/browse/ASSET-45) | Introduce Alembic schema migrations with a baseline of the current schema |
| S1.3 | [ASSET-46](https://example.atlassian.net/browse/ASSET-46) | Add linting, formatting and type checking |
| S1.4 | [ASSET-47](https://example.atlassian.net/browse/ASSET-47) | Automate dependency updates and refresh constraints.txt |
| S1.5 | [ASSET-48](https://example.atlassian.net/browse/ASSET-48) | Migrate Monitoring persistence from raw sqlite3 to SQLAlchemy |
| S2.1 | [ASSET-49](https://example.atlassian.net/browse/ASSET-49) | Review and merge login, RBAC and audit log (feature/auth-rbac-audit) |
| T2.1.1 | [ASSET-92](https://example.atlassian.net/browse/ASSET-92) | Security review checklist for auth/session/CSRF/audit code |
| T2.1.2 | [ASSET-93](https://example.atlassian.net/browse/ASSET-93) | Create first administrator on each environment after merge |
| S2.2 | [ASSET-50](https://example.atlassian.net/browse/ASSET-50) | Rate-limit login attempts per client IP |
| S2.3 | [ASSET-51](https://example.atlassian.net/browse/ASSET-51) | Force password change after administrator-set passwords |
| S2.4 | [ASSET-52](https://example.atlassian.net/browse/ASSET-52) | Personal API tokens for automation |
| S2.5 | [ASSET-53](https://example.atlassian.net/browse/ASSET-53) | View and revoke active sessions |
| S2.6 | [ASSET-54](https://example.atlassian.net/browse/ASSET-54) | Audit log retention, export and archival |
| S2.7 | [ASSET-55](https://example.atlassian.net/browse/ASSET-55) | Multi-factor authentication (TOTP) for administrators |
| S2.8 | [ASSET-56](https://example.atlassian.net/browse/ASSET-56) | Single sign-on via OIDC |
| S3.1 | [ASSET-57](https://example.atlassian.net/browse/ASSET-57) | Show asset change history to analysts on the asset detail page |
| S3.2 | [ASSET-58](https://example.atlassian.net/browse/ASSET-58) | Bulk import and export of assets (CSV) |
| S3.3 | [ASSET-59](https://example.atlassian.net/browse/ASSET-59) | Paginate the asset overview beyond 500 assets |
| S3.4 | [ASSET-60](https://example.atlassian.net/browse/ASSET-60) | Link asset owners to user accounts or teams |
| B4.1 | [ASSET-61](https://example.atlassian.net/browse/ASSET-61) | Scan targets are passed to nmap without validation (argument injection) |
| B4.2 | [ASSET-62](https://example.atlassian.net/browse/ASSET-62) | Scan schedules accept 1-second intervals and list endpoints have no upper limit |
| S4.1 | [ASSET-63](https://example.atlassian.net/browse/ASSET-63) | Restrict scans to authorised network ranges |
| S4.2 | [ASSET-64](https://example.atlassian.net/browse/ASSET-64) | Link discovered hosts to managed assets |
| T4.2.1 | [ASSET-94](https://example.atlassian.net/browse/ASSET-94) | Alembic migration: link column/table between monitoring hosts and asset_inventory |
| T4.2.2 | [ASSET-95](https://example.atlassian.net/browse/ASSET-95) | Matching service and candidate list API |
| T4.2.3 | [ASSET-96](https://example.atlassian.net/browse/ASSET-96) | UI: candidate hosts view and 'create asset from host' |
| S4.3 | [ASSET-65](https://example.atlassian.net/browse/ASSET-65) | Show monitoring results on the asset detail page |
| S4.4 | [ASSET-66](https://example.atlassian.net/browse/ASSET-66) | Scan an asset on demand and schedule recurring scans from the UI |
| T4.5 | [ASSET-67](https://example.atlassian.net/browse/ASSET-67) | Include nmap in the Docker image |
| S4.6 | [ASSET-68](https://example.atlassian.net/browse/ASSET-68) | Notify on relevant monitoring changes |
| S5.1 | [ASSET-17](https://example.atlassian.net/browse/ASSET-17) (existing) | Normalise detected and manual software to CPE identifiers |
| S5.2 | [ASSET-15](https://example.atlassian.net/browse/ASSET-15) (existing) | Retrieve CVE data from the NVD API with caching |
| S5.3 | [ASSET-20](https://example.atlassian.net/browse/ASSET-20) (existing) | Flag actively exploited CVEs using the CISA KEV catalogue |
| S5.4 | [ASSET-21](https://example.atlassian.net/browse/ASSET-21) (existing) | Findings: asset-to-CVE relationship with lifecycle |
| T5.4.1 | — | Data model and migration for findings |
| T5.4.2 | [ASSET-69](https://example.atlassian.net/browse/ASSET-69) | New permissions findings:read / findings:write in the RBAC matrix |
| S5.5 | [ASSET-70](https://example.atlassian.net/browse/ASSET-70) | Findings list and asset findings section in the UI |
| S5.6 | [ASSET-71](https://example.atlassian.net/browse/ASSET-71) | Reduce false positives from distribution backports |
| S6.1 | [ASSET-72](https://example.atlassian.net/browse/ASSET-72) | Explainable contextual risk score per finding |
| T6.4 | [ASSET-73](https://example.atlassian.net/browse/ASSET-73) | Agree on risk model weights with stakeholders |
| S6.2 | [ASSET-74](https://example.atlassian.net/browse/ASSET-74) | Recalculate risk when asset context or threat data changes |
| S6.3 | [ASSET-75](https://example.atlassian.net/browse/ASSET-75) | Risk overview: prioritised findings and riskiest assets |
| S7.1 | [ASSET-76](https://example.atlassian.net/browse/ASSET-76) | Create Jira remediation tickets from findings |
| S7.2 | [ASSET-77](https://example.atlassian.net/browse/ASSET-77) | Re-scan and verify risk reduction |
| S7.3 | [ASSET-78](https://example.atlassian.net/browse/ASSET-78) | Synchronise remediation status from Jira |
| S7.4 | [ASSET-79](https://example.atlassian.net/browse/ASSET-79) | Forward audit events and findings to Splunk/SIEM |
| S8.1 | [ASSET-80](https://example.atlassian.net/browse/ASSET-80) | Automated tests for the Monitoring module |
| S8.2 | [ASSET-81](https://example.atlassian.net/browse/ASSET-81) | Static analysis, dependency and container vulnerability scanning in CI |
| S8.3 | [ASSET-82](https://example.atlassian.net/browse/ASSET-82) | Threat model and independent security review |
| S8.4 | [ASSET-83](https://example.atlassian.net/browse/ASSET-83) | End-to-end browser tests for the web UI |
| S8.5 | [ASSET-84](https://example.atlassian.net/browse/ASSET-84) | Accessibility review of the web UI (WCAG 2.1 AA basics) |
| S8.6 | [ASSET-85](https://example.atlassian.net/browse/ASSET-85) | Concurrency test: scheduler scans and API writes on SQLite |
| S9.1 | [ASSET-87](https://example.atlassian.net/browse/ASSET-87) | TLS reverse-proxy deployment profile |
| S9.2 | [ASSET-88](https://example.atlassian.net/browse/ASSET-88) | Scheduled backups with retention and restore drill |
| T9.3 | [ASSET-89](https://example.atlassian.net/browse/ASSET-89) | Structured JSON logging option and log rotation guidance |
| T9.4 | [ASSET-90](https://example.atlassian.net/browse/ASSET-90) | Release process: versioning, changelog and image tags |
| T9.5 | [ASSET-91](https://example.atlassian.net/browse/ASSET-91) | Repository hygiene: clean up merged and parked branches |
| T8.7 | [ASSET-86](https://example.atlassian.net/browse/ASSET-86) | Clarify status of Correlation tickets marked done without code in the repository |

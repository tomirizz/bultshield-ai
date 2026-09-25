# BultShield — Stage 6

Unified Scan Engine on Bult.ai: queued jobs → worker → Gitleaks → Semgrep CE → Trivy → normalization → PostgreSQL findings. [Stage 6 architecture and deployment](docs/STAGE_6.md). [Stage 5 scope, security policy and deployment](docs/STAGE_5.md).

Public GitHub repository → shallow checkout → Gitleaks 8.30.1 + Semgrep CE 1.178.0 + Trivy 0.74.0 → redacted findings in PostgreSQL → dashboard.

The application, PostgreSQL and worker run on **Bult.ai**. The future LLM will also run on Bult; no external LLM API is used.

## Run a scan

Create a project with a public GitHub URL and branch, open it, then click **Запустить проверку**. The scan history refreshes every five seconds. Open **Результаты** for a completed scan to inspect its findings and masked evidence. Errors are shown in scan history.

Only current files in the selected branch are scanned, not Git history. No repository code is executed. No private-repository credentials are accepted. Scanner settings in the target repository do not override the trusted rules. Files above 2 MiB or a checkout above 50 MiB fail explicitly. Archives and encoded payloads are not expanded. Gitleaks detection is not proof that a credential is active; HIGH is the MVP severity policy. No findings does not guarantee security.

## Bult services

| Service | Dockerfile | Target | Network |
| --- | --- | --- | --- |
| bultshield-app | Dockerfile | app | Public HTTPS → 8080 |
| bultshield-worker | backend/Dockerfile.worker | worker | Internal; no public port or volume |
| bultshield-postgres | postgres:17-bookworm | — | Internal 5432; own persistent volume |

Both builds use repository root `.` as context. App and worker use the same private DATABASE_URL. App starts migrations; worker uses the existing schema. Do not change the initialized PostgreSQL credentials by merely editing POSTGRES_* variables. Do not delete its volume.

The shared MVP workspace has no login. Only public repositories should be scanned. At most one active scan per repository and ten jobs in the queue are accepted. The worker processes jobs serially, cleans temporary files, and updates a heartbeat every 15 seconds and marks interrupted jobs FAILED after 180 seconds without heartbeat. Findings and terminal status commit together after normalization; known scanner failures retain valid results from the other scanners and mark the overall scan FAILED. See Stage 6 for crash recovery and cleanup.

## Checks

Python 3.12; Node.js 24. Install backend/requirements-dev.txt and run `python scripts/check_backend.py` against a **local disposable *_test PostgreSQL database**. The tests refuse production databases. Run `ruff check --config backend/pyproject.toml backend scripts` and `npm ci && npm run build` inside frontend. CI additionally installs all three pinned CLIs for real positive/negative detection and masking tests.

Nuclei, AI analyses, fixes and rescan reconciliation belong to later stages. Semgrep currently covers Python and JavaScript/TypeScript with eight local rules. See docs/STAGE_5.md for exact scope and limits.

Trivy scans dependency manifests/lockfiles and Dockerfile/Kubernetes configurations. Findings retain CVE (when supplied), package, installed/fixed versions and severity. Scanner, severity, category and status filters are applied in PostgreSQL before the 100-row limit. The worker downloads the public vulnerability database into its own ephemeral cache (approximately 1.4 GiB currently; allow at least 3 GiB free for updates). Source analysis uses offline dependency resolution; stale/unavailable databases fail explicitly. No disk is added to PostgreSQL.

## Stage 7 — Security dashboard

The workspace and each project show severity and scanner totals from the latest
completed scan of each repository. Repeated runs are not added together. A failed
or running latest attempt is shown separately; previous successful results retain
their scan dates. Repositories without a successful scan are explicitly counted.

- `#/projects/<id>`: project summary, repositories and recent scan history.
- `#/findings`: searchable, paginated findings with project, scanner, severity,
  category, status and latest/all-history filters persisted in the URL.
- `#/findings/<id>`: finding details, redacted evidence, rule, CVE/CWE and package versions.
- `#/scans`: paginated history, scan status, duration, commit and scanner results.

Read-only API additions: `GET /api/security-summary` and `GET /api/findings-page`.
Both support `project_id`; findings support `scope=latest|all`, `scan_id`, `q`,
filters, `limit` and `offset`. Existing `/api/findings` retains its array response;
`/api/scans` now also accepts `offset`. No database migration is required.

# BultShield — Security Review

Unified Scan Engine on Bult.ai: queued jobs → worker → Gitleaks → Semgrep CE → Trivy → normalization → PostgreSQL findings. [Stage 6 architecture and deployment](docs/STAGE_6.md). [Stage 5 scope, security policy and deployment](docs/STAGE_5.md).

Public GitHub repository → shallow checkout → Gitleaks 8.30.1 + Semgrep CE 1.178.0 + Trivy 0.74.0 → redacted findings in PostgreSQL → dashboard.

The application, PostgreSQL and worker run on **Bult.ai**. The local LLM runs on Bult.ai; no external LLM API is used.

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

Production API access requires GitHub login; see docs/GITHUB_OAUTH_BULT.md for configuration and legacy-owner migration. Only public repositories should be scanned. At most one active scan per repository and ten jobs in the queue are accepted. The worker processes jobs serially, cleans temporary files, and updates a heartbeat every 15 seconds and marks interrupted jobs FAILED after 180 seconds without heartbeat. Findings and terminal status commit together after normalization; known scanner failures retain valid results from the other scanners and mark the overall scan FAILED. See Stage 6 for crash recovery and cleanup.

## Checks

Python 3.12; Node.js 24. Install backend/requirements-dev.txt and run `python scripts/check_backend.py` against a **local disposable *_test PostgreSQL database**. The tests refuse production databases. Run `ruff check --config backend/pyproject.toml backend scripts` and `npm ci && npm run build` inside frontend. CI additionally installs all three pinned CLIs for real positive/negative detection and masking tests.

AI analysis, reviewed fixes, isolated verification and allowlisted Nuclei checks are described below. Semgrep currently covers Python and JavaScript/TypeScript with eight local rules. See docs/STAGE_5.md for exact scope and limits.

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

## Stage 8 — AI explanations

Findings have an optional AI explanation with recommended fix, illustrative code and
remediation steps. Analysis runs separately from scanning; raw evidence, source files
and arbitrary finding text never reach the model. Inference runs on a private Bult.ai
llama.cpp service, with no external AI API. See [deployment and limits](docs/STAGE_8.md).

### Stage 9 — AI correlation

Project dashboards offer **Связанные проблемы**. The existing Bult-hosted model receives sanitized findings from the latest successful scan of each repository in one project. File/repository/package aliases preserve relationships without transmitting their raw names, source code or secrets. Each request currently covers at most 12 findings; the interface explicitly shows analyzed/total counts.

`POST /api/projects/{id}/correlation` queues a persisted `CorrelationRun`; GET returns its status and `SecurityIssueGroup` records. The shared AI queue serializes explanation and correlation inference. Groups contain validated references to original findings, separate scanner evidence, an AI hypothesis and manual verification instructions. Unknown references and duplicate/overlapping memberships reject the entire response. Empty groups are a valid outcome. Scanner findings are never rewritten. New successful scans mark older correlations stale; failed model requests are retryable.

Deployment uses the existing app and model services, with migration `0004` applied by app startup. No additional service is required. This is bounded hypothesis generation, not proof of an exploit chain or exhaustive project coverage.

### Stages 10–12 — reviewed fixes, verification, staging checks

A finding now offers **AI Fix Generator**. Generation is queued for the worker. The worker fetches the finding's exact Git commit, reads a single UTF-8 file (up to 4 KiB), checks it with Gitleaks and conservative secret patterns, and asks the private Bult-hosted model for a complete proposed file and explanation. Secret-containing context is rejected before inference/persistence. Unsupported secret/web findings remain manual. The proposal includes original/proposed source, a server-generated diff, explanation and commit. Syntax, function preservation, size and secret checks reject unsafe output; no repository code is executed.

**Approve Fix** is explicit and idempotent. It queues an isolated verification Scan Job. The worker fetches the same commit, checks the original file hash, reproduces the finding, applies the reviewed file only in scratch space, and reruns the original scanner. Matching uses scanner + rule + file (+ package for dependencies), so a line shift cannot produce a false fix. Missing coverage, errors and worker loss produce INCONCLUSIVE, never Verified Fixed. Original and verification scans are linked with a persisted timeline and Before / After counts. Verification scans do not replace source-repository dashboard snapshots. **Verified Fixed refers only to that temporary copy and scanner rule; main and the repository are unchanged, and application behavior still needs tests.** The separate fix-branch action is documented in the current stage guide; it never writes to main.

Nuclei 3.11.1 is installed from a SHA256-verified upstream release. The worker uses only three bundled GET `/` HTTP-header templates (nosniff, frame protection, HSTS), at one request/second, concurrency one, no redirects, no Interactsh, no cloud uploads, no remote templates or code/headless execution. Only exact operator-allowlisted HTTPS origins can be registered; the user must attest authorization. DNS must resolve only to global public addresses. A destination-restricted CONNECT proxy pins the vetted IP for the scan, blocking DNS rebinding/private-network access. JSONL/JSON findings are normalized to the common table with severity INFO, trusted titles and evidence descriptions; response bodies, request headers and cookies are not persisted. Empty reports are accepted only after a reachable target and a completed runner without network errors.

Deployment (existing Bult app + worker + model; no extra paid service):

- Apply app migration `0005` by rebuilding the app before starting the new worker.
- Rebuild worker with `backend/Dockerfile.worker`, context `.`.
- Set `AI_ENABLED=true`, `AI_ENDPOINT=http://bultshield-model:8080`, `AI_MODEL=qwen2.5-1.5b-instruct`, `AI_TIMEOUT_SECONDS=240` on **worker**, matching app's existing private model settings.
- Set `NUCLEI_ALLOWED_TARGETS=https://bultshield-app-bultshield-ai-brick.fin1.bult.app` on **both app and worker** for the owner-authorized demonstration. This is an exact allowlist, not a wildcard. Additional staging origins require operator configuration.
- Open a project, register the allowlisted staging address, confirm authorization and select **Проверить Nuclei**. Its separate scan appears in history and latest findings alongside static scans.

Endpoints: GET/POST `/api/findings/{id}/fix`, POST `/api/fixes/{id}/approve`, GET/POST `/api/projects/{id}/targets`, POST `/api/targets/{id}/scan`. Scan `kind` distinguishes static, verification and web jobs. Public repositories remain the supported scope. Production requests are authenticated and scoped to their project owner.


## Stages 13–20 implementation

See [implementation, limits and demonstration checklist](docs/STAGES_13_20.md) and [GitHub OAuth setup](docs/GITHUB_OAUTH_BULT.md).
Production rollout and real GitHub login must be verified separately from local tests. No external LLM service is used.

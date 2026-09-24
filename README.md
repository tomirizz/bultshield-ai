# BultShield AI — Stage 4

Gitleaks + Semgrep CE → unified PostgreSQL findings → dashboard. [Stage 4 scope, security policy and deployment](docs/STAGE_4.md).

Public GitHub repository → shallow checkout → Gitleaks 8.30.1 + Semgrep CE 1.178.0 → redacted findings in PostgreSQL → dashboard.

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

The shared MVP workspace has no login. Only public repositories should be scanned. At most one active scan per repository and ten jobs in the queue are accepted. The worker processes jobs serially, cleans temporary files, and marks interrupted jobs FAILED after 15 minutes without progress. Each scanner commits its findings and status together; successful results survive another scanner failing.

## Checks

Python 3.12; Node.js 24. Install backend/requirements-dev.txt and run `python scripts/check_backend.py` against a **local disposable *_test PostgreSQL database**. The tests refuse production databases. Run `ruff check --config backend/pyproject.toml backend scripts` and `npm ci && npm run build` inside frontend. CI additionally installs both pinned CLIs for real positive/negative detection and masking tests.

Trivy, Nuclei, AI analyses, fixes and rescan reconciliation belong to later stages. Semgrep currently covers Python and JavaScript/TypeScript with eight local rules. See docs/STAGE_4.md for exact scope and limits.

# BultShield AI

Stage 2 foundation: React dashboard, FastAPI API, and PostgreSQL. The deployment target is **Bult.ai**. Scanner execution and AI inference are intentionally not implemented at this stage.

## What works

- Create projects and save public GitHub repository URLs, branches, descriptions, and optional staging URLs.
- Add more repositories to a project; reopen and refresh the page without losing data.
- Read workspace counters, projects, scan history, findings, AI analyses, fixes, and rescans through the API.
- Apply a versioned Alembic migration for nine application tables.
- Build one Docker image containing the frontend and API. It waits for PostgreSQL and runs migrations before starting.
- Inspect liveness, database readiness, and the OpenAPI contract.

Scans and findings start empty. The scan button is disabled, and scan/rescan creation returns HTTP 501 without creating fake jobs. Saving a GitHub URL does not yet prove that the repository exists or is public.

## Deployment architecture

```text
Browser → HTTPS → bultshield-app (React build + FastAPI)
                         ↕ private PostgreSQL connection
                     postgres + its own persistent volume

Later, also on Bult.ai:
  bultshield-worker → Gitleaks / Semgrep CE / Trivy / Nuclei
  bultshield-llm    → llama.cpp + local GGUF model
```

Only App gets a public endpoint. PostgreSQL stays internal. There is no shared filesystem between services and no external LLM API. Worker and LLM are reserved for later stages and are not required to boot Stage 2.

Deployment steps and acceptance checks: [docs/BULT_DEPLOYMENT.md](docs/BULT_DEPLOYMENT.md). The repository itself is a source artifact, not evidence of a completed Bult deployment; see [docs/STATUS.md](docs/STATUS.md) for verified state.

## Repository layout

```text
backend/app/          FastAPI, validation, SQLAlchemy models
backend/migrations/   Alembic migration 0001
backend/tests/        Integration tests against real PostgreSQL
frontend/src/         React + TypeScript + Tailwind/Vite
scripts/start.sh      Database readiness, migrations, Uvicorn
Dockerfile            Multi-stage production image
compose.yaml          Local verification only
docs/                 Deployment and data/API notes
```

## Configuration

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | Required private PostgreSQL URL; `postgres://`, `postgresql://`, and `postgresql+psycopg://` are accepted. |
| `APP_ENV` | `production` on Bult, `development` locally. |
| `PORT` | HTTP port, default `8080`. Keep Bult routing consistent with it. |
| `FRONTEND_DIST` | Docker image already sets `/app/frontend/dist`. |

Never commit `.env` or database credentials. `.env.example` contains placeholders only. Percent-encode special characters in URL credentials. No API key or model download is needed for Stage 2.

## Run locally with Docker

```sh
export POSTGRES_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
docker compose up --build
```

Open `http://localhost:8080`. The database uses a persistent named volume and is not published to the host. Use the same password on subsequent starts with this volume; do not reset it accidentally. This local setup is only for verification; the actual product is deployed on Bult.ai.

## Develop and test

Use Python 3.12 and Node.js 24. Install backend dependencies from `backend/requirements-dev.txt`; frontend dependencies are locked by `frontend/package-lock.json`.

```sh
python3.12 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt
cd frontend
npm ci
npm run build
cd ..
```

For API development, set `DATABASE_URL` to a local PostgreSQL database, then run from `backend/`:

```sh
../.venv/bin/python -m app.bootstrap
../.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Use `npm run dev` in `frontend/` for a Vite development server; it proxies `/api` and `/health` to port 8080. In production FastAPI serves the compiled UI and API from the same origin.

Tests require a **disposable local database ending in `_test`**. They truncate application tables and refuse nonlocal or differently named databases:

```sh
export TEST_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@127.0.0.1:5432/bultshield_test'
.venv/bin/python scripts/check_backend.py
.venv/bin/ruff check --config backend/pyproject.toml backend scripts
cd frontend && npm run build
```

Tests exercise real persistence, constraints and project isolation at the database level, validation, duplicate handling, finding filters, related AI/fix/rescan records, and the disabled scanner contract.

## MVP access model

This version has one shared demo workspace and no registration or login, as agreed in Stage 1. The `users` table reserves ownership for later authentication. Do not treat the current public demo as a private multi-user service: visitors share the same project list. Scanner findings and AI responses cannot be submitted through write endpoints yet.

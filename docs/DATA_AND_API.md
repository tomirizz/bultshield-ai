# Data and API contract — Stage 2

## Tables

| Table | Main links and responsibility |
| --- | --- |
| `users` | Workspace owner; no login system yet. |
| `projects` | Owner, name, description, optional staging target. |
| `repositories` | Project, normalized public GitHub URL, branch. |
| `scans` | Project/repository, status, commit, configuration, per-scanner results, timestamps. |
| `findings` | Unified finding schema, evidence, original and normalized severity, fingerprint, JSON metadata. |
| `ai_analyses` | Finding, local model identifier, explanation/recommendation, analysis state. |
| `fixes` | Finding, optional analysis, description/diff, proposed/applied state and timestamp. |
| `rescans` | Original scan, verification scan, optional finding, verification outcome. |
| `scan_jobs` | Reserved PostgreSQL queue, job status, attempt count, claim/heartbeat timestamps. |

All records use UUID primary keys and UTC-aware creation timestamps. Composite foreign keys prevent a scan referencing a different project's repository and a finding referencing a different project's scan. Fixes and rescans preserve their links. PostgreSQL enforces allowed scanner, category, severity and lifecycle values.

Initial migration: `0001`. It explicitly creates tables, indexes, foreign keys and check constraints; it does not import mutable application models into the migration.

## Endpoints

| Method | Path | Behaviour |
| --- | --- | --- |
| GET | `/health/live` | Process liveness. |
| GET | `/health/ready` | Database + migration readiness. |
| GET | `/api/openapi.json` | Machine-readable API contract. |
| GET | `/api/overview` | Real counters and disabled capabilities. |
| GET / POST | `/api/projects` | List or create project; creation can include one repository atomically. |
| GET | `/api/projects/{id}` | Project and saved repositories. |
| GET / POST | `/api/projects/{id}/repositories` | List or add repository. |
| GET | `/api/scans` | Scan history, optional project filter. |
| GET | `/api/findings` | Optional project, severity, scanner, status filters. |
| GET | `/api/findings/{id}` | Unified finding. |
| GET | `/api/ai-analyses` | Optional finding filter. |
| GET | `/api/fixes` | Optional finding filter. |
| GET | `/api/rescans` | Optional project filter. |
| POST | `/api/scans`, `/api/rescans` | HTTP 501; creates no jobs until scanner execution exists. |

List endpoints have a maximum page size of 100. Projects also support `offset`. Duplicate project names or repository URLs within a project return 409. Invalid input returns 422, unknown IDs return 404, unavailable PostgreSQL returns 503. Error responses do not include credentials or SQL text.

## Lifecycle reserved for later stages

```text
Scan:
QUEUED → CLONING → SCANNING → NORMALIZING → AI_ANALYSIS → COMPLETED
Any active stage → FAILED

Finding:
OPEN → AI_ANALYZED → FIX_PROPOSED → FIX_APPLIED → RECHECKING
                                                 ├→ VERIFIED_FIXED
                                                 └→ STILL_DETECTED
```

Re-scan outcome `INCONCLUSIVE` reserves a result for failed or incomparable checks. It is not a finding status and must never be treated as `VERIFIED_FIXED`. Scanners determine detection facts; local AI explains findings and proposes changes. Execution and transition logic are future-stage work.

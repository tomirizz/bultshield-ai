# Stage 6: unified Scan Engine on Bult.ai

Production remains entirely on Bult.ai: HTTPS app (React/FastAPI), background worker
(Gitleaks, Semgrep CE, Trivy), and PostgreSQL with its existing persistent volume.
GitHub stores code and runs CI; it does not execute production scan jobs.
No new service, external queue, paid resource upgrade or LLM API is needed.

## Boundaries

`POST /api/scans` validates and inserts a Scan + its unique ScanJob in one transaction,
then returns 202. It never runs Git or a scanner. The branch is snapshotted at enqueue.
The existing `scan_jobs` table is the PostgreSQL queue; findings link to the job through
its unique `scan_id`, avoiding a duplicate scan/job lifecycle in public results.

`app.worker` owns atomic claims (`FOR UPDATE SKIP LOCKED`), worker ownership, progress,
heartbeat and persistence. One worker processes one job at a time. `app.scan_engine`
owns the sequential pipeline and the three adapters. New scanners belong in its
adapter registry, not API request handlers.

Create Scan → Clone → Gitleaks → Semgrep → Trivy → Normalize → Store → Completed.
All scanners use one checked-out commit. Public scan states are QUEUED, CLONING,
SCANNING, ANALYSING, COMPLETED and FAILED. `current_step` distinguishes scanners,
normalization and storage. Legacy NORMALIZING/AI_ANALYSIS remain readable only for
backward compatibility. Internal queue states remain QUEUED/RUNNING/COMPLETED/FAILED.

Known scanner failures do not prevent the other scanners from running. After all
scanners, valid reports are normalized and stored together, with final status FAILED
and a clear partial-results message if any scanner failed. Unexpected process loss
or normalization/storage failure before the Store transaction publishes no partial
findings. Findings and terminal state commit atomically. This replaces Stage 5's
per-scanner persistence. Earlier completed scans and their findings remain intact.
A replayed completed claim is rejected before cloning; the existing unique
(scan_id, scanner, fingerprint) constraint remains the final deduplication guard.

## Timeouts, logs and cleanup

Worker environment defaults: CLONE_TIMEOUT_SECONDS=120, GITLEAKS_TIMEOUT_SECONDS=180,
SEMGREP_TIMEOUT_SECONDS=300, TRIVY_TIMEOUT_SECONDS=600. Values must be 1..1800.
Trivy DB update and analysis share one deadline. Timeout stops and reaps the scanner
process group; findings exit codes are interpreted by each adapter.

Heartbeat every 15 seconds runs independently of scanning. After 180 seconds without
heartbeat an interrupted job is marked FAILED/WORKER_LOST. Structured JSON events
include scan/job IDs, steps, duration and sanitized errors; raw source, tokens,
scanner stdout/stderr and arbitrary exception messages are never logged.

Every engine job has its own worker-owned disk workspace under
~/.cache/bultshield-jobs (override SCAN_WORKSPACE_ROOT). Clone, snapshots and temporary
reports use this boundary and are removed on normal completion or exceptions,
before Store. Every minute the worker removes unlocked orphan directories older
than one hour. Active workers and their scanner processes hold an inherited file
lock. The shared Trivy CVE database is separate and is retained for later scans.
An abrupt kill relies on this orphan sweep rather than Python finally execution.

## Bult rollout and demo

1. Build/restart existing bultshield-app from main (Dockerfile, target app).
   Its startup applies migration 0002 without dropping old results.
2. Once app readiness reports schema 0002, build/restart bultshield-worker
   (backend/Dockerfile.worker, target worker). Existing private DATABASE_URL stays.
3. Open the public BultShield URL, select a project, and start a scan.
4. Show scan status/current step, worker JSON logs in Bult, the resulting unified
   findings, and PostgreSQL persistence after refreshing the site.
5. A successful run must show all three scanner results COMPLETED and the scanned
   commit. Logs must include workspace_cleaned before scan_finished.

## Verification

The PostgreSQL integration suite covers atomic concurrent claiming, branch snapshots,
heartbeat, lost ownership, pipeline order, atomic rollback, repeat processing,
known partial failures, crash recovery, workspace locking/cleanup, and timeouts.
Existing parser and real-CLI tests remain required. Local tests/CI are predeployment
checks, not evidence of Bult production execution; record that separately after rollout.

Trivy uses GOMEMLIMIT=32MiB and GOGC=10 on the 512 MiB Bult worker. The lower Go heap
budget leaves room for the memory-mapped vulnerability DB and Python coordinator;
this is a soft Go runtime budget, not a replacement for the container limit.

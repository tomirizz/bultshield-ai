# Stage 4 — Semgrep CE

One scan now runs Gitleaks 8.30.1 followed by Semgrep CE 1.178.0 on the same branch snapshot and commit. Both write the existing `findings` table. No migration or database reset is required. Existing Stage 3 scans remain readable.

## Trusted local rules

`backend/rules/semgrep.yaml` contains 8 original, reviewed BultShield rules for Python and JavaScript/TypeScript: dynamic eval, shell commands, pickle and unsafe YAML deserialization, disabled TLS verification, and innerHTML assignment. The JSON-formatted YAML is also the trusted source for titles, descriptions, severity and CWE. The rule bundle SHA-256 is saved with scans/findings. These patterns are review candidates, not proof of exploitability; CE has limited local analysis.

Semgrep is installed in its own environment in the worker; API dependencies remain separate. No login, cloud rules, registry fetches, external LLM API, metrics, version checks, autofix, or execution of scanned source code. The subprocess receives an allowlisted environment without DATABASE_URL or service credentials. Scan data is not uploaded to Semgrep.

## Scope and bounds

Only the current branch snapshot is checked, not Git history. Semgrep covers `.py`, `.pyi`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`. A temporary source copy excludes symlinks, repository-controlled configurations/ignore files, and `.git`, `node_modules`, `vendor`, `.venv`, `venv`, `__pycache__`, `dist`, `build` directories. Tests and fixtures are included. `nosemgrep` suppressions are disabled. Unsupported languages and dependencies are outside this rule set.

Shared limits: 2 MiB/file, 50 MiB of repository files. Semgrep: at most 5000 source files, one job, 256 MiB engine memory setting (not a whole-process limit), 5 seconds per rule/file, 240-second overall timeout, 10 MiB JSON report. A timeout kills the process group. Full reports and source copies are temporary. Only allowlisted location/rule fields survive parsing; raw lines, metavariables, fixes and interpolated messages are discarded. Evidence is `[REDACTED]` for both scanners.

The parser rejects unknown rules, paths outside the snapshot, invalid positions, wrong scanner version and incomplete/error reports. A failed scanner marks the scan FAILED, never clean. Findings and status of each successful scanner commit together and remain available if another scanner fails or the worker crashes. Details show individual errors and coverage. Zero supported files is visible as `scanned_files: 0`, not a claim about unsupported code.

## Identity and display

Fingerprint = repository + scanner + rule + file + line/column range, without source or secrets. Exact duplicates within one scanner/run collapse. Related findings from different rules or scanners remain separate. Repeated scans keep their own rows and stable fingerprints. The database uniqueness constraint additionally protects `(scan_id, scanner, fingerprint)`.

The dashboard combines both scanners, filters by scan/scanner/severity, displays CWE and each scanner's status/count. Partial results remain accessible on FAILED scans.

## Bult deployment

Use the existing app and worker; do not recreate PostgreSQL or change its disk. App: root Dockerfile, target app. Worker: backend/Dockerfile.worker, target worker, context `.`, same internal DATABASE_URL, no public ports or new volumes. Merge the validated branch and rebuild both services on main. Keep existing size S unless live measurements require a separately approved change.

Demo: scan this repository. `gitleaks-demo.env` contains the existing invented credential; `semgrep-demo.py` contains an unused eval fixture. Neither fixture is imported or run by the app. The expected Semgrep demo finding is `bultshield.python-dynamic-eval` at `semgrep-demo.py:8`. Check both scanner summaries, combined findings and persistence after page reload.

## Verification

The test suite covers JSON sanitization, path/range/report rejection, trusted configuration, environment isolation, process-group timeout, duplicate findings, same-location cross-scanner results, repeated scans, API filters, partial failures, worker crashes and real CLI positive/negative fixtures for all 8 rules. GitHub CI installs and executes both pinned CLIs.

Reference: https://semgrep.dev/docs/cli-reference

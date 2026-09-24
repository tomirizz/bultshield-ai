# Stage 5 — Trivy dependency and configuration scanning

## Pipeline and common findings

The existing worker processes Gitleaks, Semgrep CE and Trivy sequentially on the same branch snapshot and commit. Trivy 0.74.0 is downloaded from the official release with pinned SHA256 for Linux amd64 and arm64. No Trivy GitHub setup action or floating release tag is used. JSON schema v2 filesystem reports are parsed through a field allowlist; no migration is required.

- Dependency rows: vulnerability identifier, CVE when the identifier is a CVE, severity, package, installed version, fixed version(s), ecosystem and manifest path. A GHSA or other advisory is retained as the rule ID without inventing a CVE. An absent fix stays null and is shown explicitly.
- Configuration rows: failed Dockerfile/Kubernetes checks, rule ID, severity and available line range. Full-line trivy/tfsec ignore comments are disabled in the temporary copy without moving line numbers; inline ignore directives fail explicitly rather than hiding a check or modifying a possible YAML value. PASS checks do not create findings.
- Raw messages, source snippets, configuration values, URLs, raw JSON and subprocess logs are not persisted. Evidence is `[REDACTED]`.
- Fingerprints distinguish scanner, repository, category, file, rule, package identity/version and location. Exact duplicates within a scan collapse. Repeated scans retain separate rows with stable fingerprints. A scanner's findings and success status commit atomically; another scanner failing leaves successful results accessible.
- Scanner, severity, category and status filters combine with AND and run in PostgreSQL before the 100-row limit, including when viewing a particular scan. Existing finding lifecycle statuses are preserved; this stage adds filtering, not a status-editing workflow.

## Supported scope

The worker copies only supported manifests and configuration files into a temporary snapshot. Dependency inputs include requirements*.txt, Pipfile.lock, poetry.lock, uv.lock/pyproject.toml, npm package-lock.json/package.json, yarn.lock, pnpm-lock.yaml, go.mod/go.sum, Cargo.lock, Gemfile.lock and composer.lock. Actual vulnerability coverage depends on Trivy recognizing a manifest and concrete versions; unlocked/ranged dependencies are not a complete dependency inventory. Development dependencies are included where supported.

Configuration scanners: Dockerfile (including Dockerfile.* / *.Dockerfile) and Kubernetes YAML. Other YAML is not claimed as covered. No container image, operating-system package, archive, Java binary, Terraform, Helm or remote-module scan is enabled. Input file count is not a claim that every input file has an applicable analyzer. `result_files` counts report targets, not all analyzed files.

Repository `.trivyignore`, Trivy settings, Rego policies, modules, symlinks, installed dependency trees and build output cannot override the trusted scan configuration. No package install, repository build, fix or repository program runs. The child environment excludes database credentials and scanner tokens. Temporary source copies/reports/logs are removed after each run.

## Database, limits and failure handling

A separate step refreshes Trivy's public vulnerability database without a source target. It uses only the CLI's official registry defaults. The cache is worker-owned, separate from PostgreSQL, reused between jobs and lost on worker replacement. Temporary OCI downloads, extraction and scan files are placed under this disk-backed cache directory instead of the platform default /tmp, which may be memory-backed. Database update date is recorded; data older than 24 hours, download failures, malformed reports and scanner failures produce FAILED, never a clean zero-findings success. A failed mirror may fall back to another official mirror; the update must exit successfully, metadata must be fresh and the scan must open the database. Cached data is not silently accepted after an overall update failure.

The scan then uses `--offline-scan`, skips DB/Java DB/check/VEX updates, disables telemetry/version checks, and uses embedded configuration checks. Repository contents are not uploaded. This is CLI configuration, not an operating-system network sandbox. Embedded-check fallback on an empty cache and skipped pip license detection (licenses are outside this scan scope) are expected diagnostics; other WARN/ERROR/FATAL diagnostics fail conservatively to avoid silent parse failures.

Limits: existing 2 MiB/file and 50 MiB checkout; 5,000 supported input files; one scan goroutine; Go memory target 96 MiB with earlier garbage collection (not a hard process limit); 300 seconds each for DB update and scan; 20 MiB JSON and 2 MiB diagnostics. Timeout/oversize kills the subprocess group. After abrupt worker termination, the existing job recovery marks a job failed after 15 minutes without progress and retains completed scanner findings; a new scan is then allowed. Safe phase-only Trivy logs identify DB update versus analysis without revealing repository content. Deploy with a container memory limit; validated target is the existing 512 MiB / 0.25 CPU worker. Database cache currently uses about 1.4 GiB; reserve at least 3 GiB free ephemeral disk for download/update overhead. No additional paid volume or service is required by this change.

## Validation and deployment

Tests cover real vulnerable dependencies and built-in Dockerfile rules, hostile repository settings, field sanitization, advisory/no-fix handling, malformed reports, stale database, timeouts, same-finding duplicates, package versions, repeated scans, filters before limit, and partial failure with Gitleaks/Semgrep retained. CI installs all three real CLIs and runs PostgreSQL tests.

Build existing app from root Dockerfile target app; worker from backend/Dockerfile.worker target worker; both use root context and main branch. Preserve the existing private DATABASE_URL and PostgreSQL volume. After deployment, run a public-repository scan, verify all three statuses, CVE/package/version details, all filters and persistence after reload. Actual execution evidence is recorded in the delivery report; this document describes behavior and acceptance criteria.

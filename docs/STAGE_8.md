# Stage 8 — AI explanations on Bult.ai

Scanning remains independent. An explicit request on a finding creates a durable
PostgreSQL AIAnalysis job. AI Analysis Service runs a background consumer in the
application process and calls a private llama.cpp service. It never runs scanners
or modifies repositories. The API only enqueues work and returns immediately.

## Deployment

- Model service: existing GitHub repository, context `.`, Dockerfile `ai/Dockerfile`,
  target `model`, internal port 8080 only; **no public port/domain**. Start with L
  (1 vCPU, 2 GB RAM; Bult displayed $24/month on 2026-09-25).
- Model: official Qwen2.5-1.5B-Instruct Q4_K_M, pinned revision and SHA256 in Dockerfile.
  Weights are in the image; no shared volume or model API subscription is needed.
- Runtime: official llama.cpp server image pinned by digest. Context 4096; parallel 1.
- Application environment: `AI_ENABLED=true`, `AI_ENDPOINT=http://<actual-private-host>:8080`,
  `AI_MODEL=qwen2.5-1.5b-instruct`, optional `AI_TIMEOUT_SECONDS=240` (10–600).
  Obtain the private hostname from Bult; do not guess it or expose the model publicly.
- Rebuild the application. Its bootstrap applies migration 0003. Existing scan worker
  remains compatible; no worker rebuild is required.

## API and data handling

`GET /api/ai-status`; `GET|POST /api/findings/{id}/analysis`.
POST returns an existing pending/running/completed result; failed jobs can be retried.
An advisory lock serializes admission, and a partial unique index prevents active
duplicates. At most five queued/running analyses are allowed, one inference at a time.
Interrupted work becomes failed after its timeout plus 60 seconds; queued jobs survive
application restarts. Failures never alter scan/finding status or create fixes.

The model receives normalized enums, approved descriptions from the trusted local
rule catalog, validated numeric CVE/CWE identifiers, language and line number.
Arbitrary titles, descriptions, paths, metadata, source code and evidence are **not**
transmitted. Location remains visible from the original finding in the UI. This is
intentionally stricter than attempting to redact arbitrary source text with regexes.
Model output is schema/length validated; incomplete output and credential-shaped
material are rejected. No prompts, responses or provider exception text are logged.
Only private RFC1918/ULA/loopback addresses are accepted. Connections bypass proxies,
use the validated IP and do not follow redirects. No external model fallback exists.

The UI displays model identity, generated-content disclosure, explanation, risk,
checks, recommended fix, illustrative code and remediation steps. React renders
output as text, not HTML. Suggestions are not proof of exploitability or verified fixes.
The small model's explanations require human review, especially CVE-specific advice.

## Sources

- https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF
- https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md

## Verification

Run the usual backend suite and frontend build. AI tests cover redaction by omission,
queue admission/idempotency, retry, stale jobs, private-only endpoints, output validation
and independence from finding status. A real inference on Bult is additionally required
before reporting this stage as production verified.

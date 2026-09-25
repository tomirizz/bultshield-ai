"""Sequential pipeline. Queue ownership and persistence belong to the worker."""
import json
import time
from dataclasses import dataclass

from .finding_normalizer import normalize_gitleaks, normalize_semgrep, normalize_trivy
from .gitleaks_runner import GitleaksError, run_gitleaks
from .models import ScanStatus
from .repository_checkout import checkout_repository
from .scan_runtime import job_workspace
from .scanner_catalog import RULES_SHA256, SEMGREP_VERSION, TRIVY_VERSION
from .semgrep_runner import SemgrepError, run_semgrep
from .trivy_runner import TrivyError, run_trivy


def log_event(data, event, **fields):
    # Only engine-owned fields: no exception repr, source, URLs, stdout or stderr.
    print(json.dumps({'event': event, 'scan_id': str(data.scan_id), 'job_id': str(data.job_id), **fields}), flush=True)


@dataclass(frozen=True)
class ScannerAdapter:
    name: str
    run: object
    normalize: object
    error: type[Exception]
    version: str


def adapters():
    return (
        ScannerAdapter('gitleaks', run_gitleaks, normalize_gitleaks, GitleaksError, '8.30.1'),
        ScannerAdapter('semgrep', run_semgrep, normalize_semgrep, SemgrepError, SEMGREP_VERSION),
        ScannerAdapter('trivy', run_trivy, normalize_trivy, TrivyError, TRIVY_VERSION),
    )


def run_pipeline(data, progress, store):
    started = time.monotonic()
    log_event(data, 'scan_started')
    reports, summaries, findings = [], {}, []
    with job_workspace(data.job_id):
        progress(data, ScanStatus.CLONING, step='clone')
        with checkout_repository(data.url, data.branch) as (repository, commit_sha):
            for adapter in adapters():
                progress(data, ScanStatus.SCANNING, commit_sha=commit_sha, step=adapter.name,
                         scanner_result=(adapter.name, {'status': 'RUNNING'}))
                began = time.monotonic()
                log_event(data, 'step_started', step=adapter.name)
                try:
                    report = adapter.run(repository)
                    reports.append((adapter, report))
                    summary = {'status': 'ANALYSING', 'version': adapter.version,
                               'scope': 'branch_snapshot', 'source_redacted': True}
                    if adapter.name == 'semgrep':
                        summary.update(scanned_files=report.scanned_files, rules_sha256=RULES_SHA256)
                    elif adapter.name == 'trivy':
                        summary.update(report.summary)
                    else:
                        summary['secrets_redacted'] = True
                except adapter.error as exc:
                    summary = {'status': 'FAILED', 'error': str(exc), 'error_code': 'SCANNER_FAILED'}
                summary['duration_seconds'] = round(time.monotonic() - began, 3)
                summaries[adapter.name] = summary
                progress(data, ScanStatus.SCANNING, step=adapter.name, scanner_result=(adapter.name, summary))
                log_event(data, 'step_finished', step=adapter.name, status=summary['status'],
                          duration_seconds=summary['duration_seconds'], error_code=summary.get('error_code'), error=summary.get('error'))
            progress(data, ScanStatus.ANALYSING, step='normalize')
            log_event(data, 'step_started', step='normalize')
            for adapter, report in reports:
                results = report if adapter.name == 'gitleaks' else report.findings
                normalized = adapter.normalize(results, project_id=data.project_id, repository_id=data.repository_id,
                                               scan_id=data.scan_id, commit_sha=commit_sha)
                findings.extend(normalized)
                summaries[adapter.name].update(status='COMPLETED', finding_count=len(normalized))
            progress(data, ScanStatus.ANALYSING, step='store')
    # Source and raw reports are gone before the atomic Store + terminal-state commit.
    log_event(data, 'workspace_cleaned')
    log_event(data, 'step_started', step='store')
    store(data, findings, summaries)
    log_event(data, 'scan_finished', status='FAILED' if any(s['status'] == 'FAILED' for s in summaries.values()) else 'COMPLETED',
              duration_seconds=round(time.monotonic() - started, 3))

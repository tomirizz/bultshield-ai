"""Задание проверки образа: запуск Trivy, нормализация находок, сохранение результата.

Сбой сканера сохраняется как FAILED и никогда не превращается в «уязвимостей нет».
"""
import hashlib
import json
import time

from .image_scan import ImageScanError, run_image_scan
from .models import Category, Finding, FindingStatus, Scanner, ScanStatus, Severity
from .scan_engine import log_event
from .scanner_catalog import TRIVY_VERSION

APP_DESCRIPTION = ('Известная уязвимость в зависимости приложения внутри Docker-образа. '
                   'Обновление пакета нужно проверить в изолированной среде.')


def normalize_image_findings(results, *, project_id, repository_id, scan_id, image, digest):
    """Находки из отчёта по образу -> записи Finding. Отпечаток включает digest образа."""
    findings, seen = [], set()
    for result in results:
        identity = {'repository_id': str(repository_id), 'scanner': Scanner.TRIVY.value, 'source': 'image',
                    'image_digest': digest,
                    **{key: result.get(key) for key in ('category', 'rule_id', 'file', 'package',
                                                       'installed_version', 'package_id', 'ecosystem')}}
        fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        reason = result.get('manual_reason')
        metadata = {key: result.get(key) for key in ('origin', 'ecosystem', 'package', 'installed_version',
                                                    'fixed_version', 'package_id', 'fix_status', 'manual_reason')}
        metadata.update(repository_id=str(repository_id), commit_sha=None, scanner_version=TRIVY_VERSION,
                        scan_scope='registry_image', source='image', image=image, image_digest=digest,
                        source_redacted=True, severity_source='trivy', review_required=True)
        findings.append(Finding(
            project_id=project_id, scan_id=scan_id, scanner=Scanner.TRIVY, category=Category.DEPENDENCY,
            title=f"{result['rule_id']}: {result['package']}"[:300],
            description=(f'Автоматическое исправление недоступно: {reason}.' if reason else APP_DESCRIPTION),
            severity=Severity(result['severity']), original_severity=result['severity'], file=result['file'],
            rule_id=result['rule_id'], cve=result.get('cve'), cwe=None, evidence='[REDACTED]',
            status=FindingStatus.OPEN, fingerprint=fingerprint, extra=metadata,
        ))
    return findings


def run_image_pipeline(data, progress, store):
    started = time.monotonic()
    log_event(data, 'scan_started')
    reference = (data.config.get('image') or {}).get('reference')
    progress(data, ScanStatus.SCANNING, step='trivy', scanner_result=('trivy', {'status': 'RUNNING'}))
    log_event(data, 'step_started', step='trivy')
    began = time.monotonic()
    findings = []
    try:
        result = run_image_scan(reference)
        findings = normalize_image_findings(
            result.report.findings, project_id=data.project_id, repository_id=data.repository_id,
            scan_id=data.scan_id, image=result.reference, digest=result.digest)
        summary = {**result.summary, 'status': 'COMPLETED', 'version': TRIVY_VERSION, 'source_redacted': True,
                   'finding_count': len(findings)}
    except ImageScanError as exc:
        summary = {'status': 'FAILED', 'error': str(exc), 'error_code': 'SCANNER_FAILED'}
    summary['duration_seconds'] = round(time.monotonic() - began, 3)
    progress(data, ScanStatus.SCANNING, step='trivy', scanner_result=('trivy', summary))
    log_event(data, 'step_finished', step='trivy', status=summary['status'],
              duration_seconds=summary['duration_seconds'], error_code=summary.get('error_code'),
              error=summary.get('error'))
    progress(data, ScanStatus.ANALYSING, step='store')
    log_event(data, 'step_started', step='store')
    store(data, findings, {'trivy': summary})
    log_event(data, 'scan_finished', status=summary['status'], duration_seconds=round(time.monotonic() - started, 3))

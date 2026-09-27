"""Static recheck on the exact source commit, with an approved patch in scratch space."""
import hashlib
from uuid import UUID

from sqlalchemy import select

from .fix_service import FixError, source_file, transition, validate_proposal
from .models import Finding, FindingStatus, Fix, Rescan, ScanStatus
from .repository_checkout import checkout_repository
from .scan_engine import adapters, log_event
from .scan_runtime import job_workspace


def matches(original, current):
    # A line shift never counts as a fix. Conservatively retain any match of the same rule/file/package.
    return (original.scanner == current.scanner and original.rule_id == current.rule_id and original.file == current.file
            and (original.category.value != 'dependency' or original.extra.get('package') == current.extra.get('package')))


def normalized(adapter, repository, data, sha, filename=None):
    report = adapter.run(repository)
    if adapter.name == 'trivy' and filename not in report.summary.get('covered_files', []):
        raise FixError('Trivy не подтвердил проверку изменённого файла. Результат не определён.')
    raw = report if adapter.name == 'gitleaks' else report.findings
    return adapter.normalize(raw, project_id=data.project_id, repository_id=data.repository_id, scan_id=data.scan_id, commit_sha=sha)


def run_verification(data, progress, store):
    from .worker import active_records, sessions
    with sessions()() as db:
        fix = db.get(Fix, UUID(data.config['fix_id']))
        if not fix or fix.verification_scan_id != data.scan_id or not fix.approved_at or fix.status != 'APPROVED':
            raise FixError('Нет одобренного исправления для этой проверки.')
        original = db.get(Finding, fix.finding_id)
        adapter = next(a for a in adapters() if a.name == original.scanner.value)
        filename, original_hash, proposed, sha = fix.file, fix.original_hash, fix.proposed, fix.base_sha
    with job_workspace(data.job_id):
        progress(data, ScanStatus.CLONING, step='clone')
        with checkout_repository(data.url, data.branch, commit=sha) as (repository, commit):
            path, source = source_file(repository, filename)
            if hashlib.sha256(source.encode()).hexdigest() != original_hash:
                raise FixError('Исходный файл не совпадает с одобренной версией.')
            progress(data, ScanStatus.SCANNING, commit_sha=commit, step='baseline', scanner_result=(adapter.name, {'status': 'RUNNING'}))
            before = normalized(adapter, repository, data, commit, filename)
            old_matches = [f for f in before if matches(original, f)]
            if not old_matches:
                raise FixError('Исходная находка не воспроизвелась. Исправление не подтверждено.')
            validate_proposal(source, proposed, filename)
            path.write_bytes(proposed.encode('utf-8'))
            with sessions().begin() as db:
                active_records(db, data)
                record = db.get(Fix, fix.id)
                transition(record, 'APPLIED')
                from .worker import now
                record.applied_at = now()
                db.get(Finding, original.id).status = FindingStatus.FIX_APPLIED
            with sessions().begin() as db:
                active_records(db, data)
                transition(db.get(Fix, fix.id), 'RECHECKING')
                db.get(Finding, original.id).status = FindingStatus.RECHECKING
            progress(data, ScanStatus.SCANNING, step=adapter.name)
            after = normalized(adapter, repository, data, commit, filename)
            # Scanner success alone is insufficient if it silently skipped the modified file.
            if not path.is_file() or path.read_bytes() != proposed.encode():
                raise FixError('Изменённый файл недоступен для повторной проверки.')
            remaining = [f for f in after if matches(original, f)]
            verdict = 'STILL_DETECTED' if remaining else 'VERIFIED_FIXED'
            details = {'scope': 'isolated_copy', 'base_sha': sha, 'before_matches': len(old_matches),
                       'after_matches': len(remaining), 'before_total': len(before), 'after_total': len(after),
                       'scanner': adapter.name, 'rule_id': original.rule_id, 'file': filename,
                       'outcome': verdict, 'repository_changed': False,
                       'note': 'Проверено только статическим сканером во временной копии. Тесты приложения не выполнялись.'}
            summary = {adapter.name: {'status': 'COMPLETED', 'version': adapter.version, 'finding_count': len(after), 'scope': 'isolated_copy'}}
            progress(data, ScanStatus.ANALYSING, step='store')
    # Store scan and verification verdict in the SAME owned transaction.
    store(data, after, summary, verification=(fix.id, details))
    log_event(data, 'verification_completed', outcome=verdict)


def finish(db, data, fix_id, details):
    fix = db.get(Fix, fix_id)
    fix.verification = details
    transition(fix, details['outcome'])
    finding = db.get(Finding, fix.finding_id)
    finding.status = FindingStatus(details['outcome'])
    finding.extra = {**finding.extra, 'verification_scope': 'isolated_copy', 'verification_scan_id': str(data.scan_id)}
    rescan = db.scalar(select(Rescan).where(Rescan.verification_scan_id == data.scan_id))
    rescan.outcome = details['outcome']


def failed(db, scan, message):
    if scan.kind != 'verification':
        return
    fix = db.scalar(select(Fix).where(Fix.verification_scan_id == scan.id))
    if fix:
        transition(fix, 'FAILED')
        fix.error_message = message
        fix.verification = {**fix.verification, 'outcome': 'INCONCLUSIVE', 'scope': 'isolated_copy', 'repository_changed': False}
        db.get(Finding, fix.finding_id).status = FindingStatus.FIX_PROPOSED
    rescan = db.scalar(select(Rescan).where(Rescan.verification_scan_id == scan.id))
    if rescan:
        rescan.outcome = 'INCONCLUSIVE'

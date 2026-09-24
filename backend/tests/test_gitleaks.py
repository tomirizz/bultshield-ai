import json
import shutil
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from app import worker
from app.gitleaks_runner import GitleaksError, _sanitize_finding, run_gitleaks
from app.models import Finding, Scan, ScanJob, ScanStatus
from app.repository_checkout import RepositoryCheckoutError, checkout_repository
from app.semgrep_runner import SemgrepReport
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker


def project_and_scan(client, branch="main"):
    project = client.post('/api/projects', json={
        'name': 'Gitleaks integration',
        'repository': {'url': 'https://github.com/example/demo', 'default_branch': branch},
    }).json()
    result = client.post('/api/scans', json={'repository_id': project['repositories'][0]['id']})
    assert result.status_code == 202, result.text
    return result.json()


@pytest.fixture
def worker_db(engine, monkeypatch):
    monkeypatch.setattr(worker, 'sessions', lambda: sessionmaker(bind=engine, expire_on_commit=False))
    monkeypatch.setattr(worker, 'run_semgrep', lambda path: SemgrepReport([], 0))


def sanitized(root):
    return _sanitize_finding({
        'RuleID': 'github-pat', 'Description': 'Possible GitHub token',
        'File': str(root / 'demo.env'), 'StartLine': 1, 'EndLine': 1,
        'StartColumn': 1, 'EndColumn': 40,
        'Secret': 'raw-sensitive-value', 'Match': 'raw-sensitive-value',
        'Fragment': 'raw-sensitive-value',
    }, root)


def test_report_whitelist_removes_all_secret_fields(tmp_path):
    finding = sanitized(tmp_path)
    assert 'raw-sensitive-value' not in json.dumps(finding)
    assert 'Fragment' not in finding
    assert finding['Secret'] == finding['Match'] == '[REDACTED]'
    with pytest.raises(GitleaksError):
        _sanitize_finding({**finding, 'File': '../outside.env'}, tmp_path)


def test_checkout_rejects_non_github_before_launch():
    with pytest.raises(RepositoryCheckoutError):
        with checkout_repository('http://127.0.0.1/private'):
            pytest.fail('Must reject URL')


def test_worker_persists_redacted_findings_and_deduplicates(client, db, worker_db, monkeypatch, tmp_path):
    scan = project_and_scan(client)

    @contextmanager
    def checkout(url, branch):
        yield tmp_path, 'a' * 40

    monkeypatch.setattr(worker, 'checkout_repository', checkout)
    monkeypatch.setattr(worker, 'run_gitleaks', lambda path: [sanitized(path), sanitized(path)])
    job = worker.claim_job()
    assert job is not None
    assert worker.claim_job() is None
    worker.process_job(job)
    result = client.get('/api/scans').json()[0]
    assert result['status'] == 'COMPLETED'
    assert result['commit_sha'] == 'a' * 40
    assert result['scanner_results']['gitleaks']['finding_count'] == 1
    findings = client.get('/api/findings', params={'scan_id': scan['id']}).json()
    assert len(findings) == 1
    assert findings[0]['evidence'] == '[REDACTED]'
    assert 'raw-sensitive-value' not in json.dumps(findings)
    assert findings[0]['metadata']['credential_validity'] == 'not_checked'
    assert db.scalar(select(ScanJob.status)) == 'COMPLETED'
    assert client.get('/api/findings', params={'scan_id': '00000000-0000-4000-8000-000000000099'}).json() == []


def test_worker_failure_never_creates_clean_success(client, db, worker_db, monkeypatch):
    scan = project_and_scan(client)

    @contextmanager
    def fail_checkout(url, branch):
        raise RepositoryCheckoutError('Репозиторий недоступен.')
        yield

    monkeypatch.setattr(worker, 'checkout_repository', fail_checkout)
    worker.process_job(worker.claim_job())
    result = client.get('/api/scans').json()[0]
    assert result['status'] == 'FAILED'
    assert result['error_message'] == 'Репозиторий недоступен.'
    assert db.scalar(select(func.count()).select_from(Finding)) == 0
    assert client.post('/api/scans', json={'repository_id': scan['repository_id']}).status_code == 202


def test_stale_worker_job_recovers_as_failed(client, db, worker_db):
    scan = project_and_scan(client)
    job = worker.claim_job()
    record = db.get(ScanJob, job.job_id)
    record.heartbeat_at = datetime.now(timezone.utc) - timedelta(minutes=16)
    db.commit()
    worker.recover_stale_jobs()
    db.expire_all()
    assert db.get(Scan, UUID(scan['id'])).status == ScanStatus.FAILED
    assert db.get(ScanJob, job.job_id).status == 'FAILED'


@pytest.mark.skipif(shutil.which('gitleaks') is None, reason='Real CLI runs in worker container')
def test_real_gitleaks_clean_and_redacted(tmp_path):
    (tmp_path / 'README.md').write_text('A clean project.\n')
    assert run_gitleaks(tmp_path) == []
    synthetic = 'ghp_' + '7Q9zK2mR8vX4nB6cD3fG5hJ1pL0sT9wY6uA2'
    (tmp_path / 'demo.env').write_text(f'GITHUB_TOKEN={synthetic}\n')
    # Repository-controlled suppression must not hide the finding.
    (tmp_path / '.gitleaks.toml').write_text('[allowlist]\npaths = [".*"]\n')
    findings = run_gitleaks(tmp_path)
    assert any(item['RuleID'] == 'github-pat' for item in findings)
    assert synthetic not in json.dumps(findings)
    assert all(item['Secret'] == '[REDACTED]' for item in findings)
    (tmp_path / 'large.bin').write_bytes(b'x' * (2 * 1024 * 1024 + 1))
    with pytest.raises(GitleaksError, match='2 МБ'):
        run_gitleaks(tmp_path)

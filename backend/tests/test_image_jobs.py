import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from app import image_pipeline, worker
from app.image_jobs import create_image_scan
from app.image_report import parse_image_report
from app.image_scan import ImageScanError, ImageScanResult
from app.models import Finding, Scan, ScanJob, ScanStatus
from app.security_dashboard import latest_scans
from fastapi import HTTPException
from sqlalchemy import func, select, update
from test_gitleaks import project_and_scan
from test_gitleaks import worker_db as worker_db

FIXTURE = Path(__file__).parent / 'fixtures' / 'trivy_image_report.json'
DIGEST = 'sha256:1566a7c1278013df557f3a960691911f1b4708c7015238c44ad0e16ada5bfb4e'
REFERENCE = 'localhost:5001/bultshield-demo-app:main'


@pytest.fixture(autouse=True)
def allow_local_registry(monkeypatch):
    monkeypatch.setenv('IMAGE_ALLOWED_REGISTRIES', 'localhost:5001')


def repository(client):
    project = client.post('/api/projects', json={
        'name': 'Image scans',
        'repository': {'url': 'https://github.com/example/demo', 'default_branch': 'main'},
    }).json()
    return UUID(project['repositories'][0]['id'])


def scan_result():
    report = parse_image_report(json.loads(FIXTURE.read_text()))
    return ImageScanResult(REFERENCE, DIGEST, 'linux/amd64', '2026-10-06T07:04:23Z', report)


def test_image_job_runs_through_the_worker(client, db, worker_db, monkeypatch):
    scan = create_image_scan(db, repository(client), REFERENCE)
    monkeypatch.setattr(image_pipeline, 'run_image_scan', lambda reference: scan_result())
    job = worker.claim_job()
    assert job.kind == 'image' and job.config['image']['reference'] == REFERENCE
    worker.process_job(job)
    stored = client.get('/api/scans').json()[0]
    assert stored['kind'] == 'image' and stored['status'] == 'COMPLETED'
    assert stored['scanner_results']['trivy']['digest'] == DIGEST
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    assert len(findings) == 14 and all(f.risk_score is not None for f in findings)
    assert len(client.get('/api/findings', params={'scan_id': str(scan.id)}).json()) == 14


def test_failed_image_scan_is_failed_not_clean(client, db, worker_db, monkeypatch):
    scan = create_image_scan(db, repository(client), REFERENCE)

    def fail(reference):
        raise ImageScanError('Trivy завершился с ошибкой (1); проверка неполная.')
    monkeypatch.setattr(image_pipeline, 'run_image_scan', fail)
    worker.process_job(worker.claim_job())
    stored = client.get('/api/scans').json()[0]
    assert stored['status'] == 'FAILED' and stored['error_code'] == 'SCANNER_FAILED'
    assert stored['scanner_results']['trivy']['status'] == 'FAILED'
    assert db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all() == []


def test_image_scan_does_not_replace_source_snapshot(client, db, worker_db, monkeypatch):
    static = project_and_scan(client)
    db.execute(update(ScanJob).where(ScanJob.scan_id == UUID(static['id'])).values(status='COMPLETED'))
    db.execute(update(Scan).where(Scan.id == UUID(static['id'])).values(status=ScanStatus.COMPLETED))
    db.commit()
    image = create_image_scan(db, UUID(static['repository_id']), REFERENCE)
    monkeypatch.setattr(image_pipeline, 'run_image_scan', lambda reference: scan_result())
    worker.process_job(worker.claim_job())
    selected = set(db.scalars(latest_scans(UUID(static['project_id']), completed_only=True)))
    assert selected == {UUID(static['id']), image.id}


def test_repeated_request_returns_the_same_scan(client, db):
    repo_id = repository(client)
    first = create_image_scan(db, repo_id, REFERENCE)
    assert create_image_scan(db, repo_id, REFERENCE).id == first.id
    assert db.scalar(select(func.count()).select_from(ScanJob)) == 1


def test_invalid_requests_create_nothing(client, db):
    repo_id = repository(client)
    for reference in ('evil.example.com/app:main', 'not a reference'):
        with pytest.raises(HTTPException) as error:
            create_image_scan(db, repo_id, reference)
        assert error.value.status_code == 422
    with pytest.raises(HTTPException) as error:
        create_image_scan(db, uuid4(), REFERENCE)
    assert error.value.status_code == 404
    assert db.scalar(select(func.count()).select_from(Scan)) == 0

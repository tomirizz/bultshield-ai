import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from app import scan_engine, scan_runtime, worker
from app.models import Repository, ScanJob
from sqlalchemy import select
from test_gitleaks import project_and_scan
from test_gitleaks import worker_db as worker_db
from test_semgrep import install_scan_mocks


@pytest.fixture(autouse=True)
def scratch(monkeypatch, tmp_path):
    monkeypatch.setenv('SCAN_WORKSPACE_ROOT', str(tmp_path / 'jobs'))


def test_queue_only_and_branch_snapshot(client, db, worker_db, monkeypatch):
    monkeypatch.setattr(scan_engine, 'run_pipeline', lambda *a: pytest.fail('API must only enqueue'))
    scan = project_and_scan(client, branch='release')
    assert scan['status'] == 'QUEUED'
    job = db.scalar(select(ScanJob))
    assert job.status == 'QUEUED' and job.locked_at is None
    repository = db.get(Repository, UUID(scan['repository_id']))
    repository.default_branch = 'changed-after-enqueue'
    db.commit()
    claimed = worker.claim_job()
    assert claimed.branch == 'release'


def test_two_workers_claim_once(client, worker_db):
    project_and_scan(client)
    barrier = threading.Barrier(2)
    def claim():
        barrier.wait()
        return worker.claim_job()
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda _: claim(), range(2)))
    assert sum(result is not None for result in results) == 1


def test_pipeline_order_atomic_store_cleanup_and_replay(client, worker_db, monkeypatch, tmp_path):
    scan = project_and_scan(client)
    install_scan_mocks(monkeypatch, tmp_path)
    steps = []
    original = worker.update_progress
    def progress(data, status, **kw):
        assert client.get('/api/findings', params={'scan_id': scan['id']}).json() == []
        steps.append((status.value, kw['step']))
        original(data, status, **kw)
    monkeypatch.setattr(worker, 'update_progress', progress)
    original_store = worker.store_results
    def store(*args):
        assert list(scan_runtime.workspace_root().iterdir()) == []
        original_store(*args)
    monkeypatch.setattr(worker, 'store_results', store)
    data = worker.claim_job()
    worker.process_job(data)
    assert [step for i, (_, step) in enumerate(steps) if not i or steps[i-1][1] != step] == [
        'clone', 'gitleaks', 'semgrep', 'trivy', 'normalize', 'store']
    assert ('ANALYSING', 'normalize') in steps
    before = client.get('/api/findings', params={'scan_id': scan['id']}).json()
    worker.process_job(data)
    assert client.get('/api/findings', params={'scan_id': scan['id']}).json() == before
    assert client.get('/api/scans').json()[0]['current_step'] == 'completed'


def test_live_heartbeat_prevents_false_recovery(client, db, worker_db, monkeypatch):
    project_and_scan(client)
    data = worker.claim_job()
    job = db.get(ScanJob, data.job_id)
    job.heartbeat_at = datetime.now(timezone.utc) - timedelta(minutes=16)
    db.commit()
    pulsed = threading.Event()
    original = worker.heartbeat
    def pulse(data):
        original(data)
        pulsed.set()
    monkeypatch.setattr(worker, 'heartbeat', pulse)
    monkeypatch.setattr(worker, 'HEARTBEAT_SECONDS', 0.01)
    with worker.keep_alive(data):
        assert pulsed.wait(2)
        worker.recover_stale_jobs()
    db.expire_all()
    assert db.get(ScanJob, data.job_id).status == 'RUNNING'


def test_lost_ownership_cannot_publish(client, db, worker_db):
    project_and_scan(client)
    data = worker.claim_job()
    job = db.get(ScanJob, data.job_id)
    job.worker_id = str(uuid4())
    db.commit()
    with pytest.raises(worker.JobNoLongerActive):
        worker.store_results(data, [], {})


def test_cleanup_after_exception_and_orphan_lock(tmp_path):
    with pytest.raises(RuntimeError):
        with scan_runtime.job_workspace(uuid4()) as root:
            with scan_runtime.temporary_directory(prefix='report-') as report:
                assert str(root) in report
            scan_runtime.cleanup_orphans(min_age=0)
            assert root.exists()  # active lock protects it even with no grace period
            raise RuntimeError('simulated failure')
    assert not root.exists()
    orphan = scan_runtime.workspace_root() / f'{uuid4()}-orphan'
    orphan.mkdir()
    (orphan / '.lock').touch()
    (orphan / 'source').write_text('test')
    scan_runtime.cleanup_orphans(min_age=0)
    assert not orphan.exists()


def test_process_timeout_kills_and_reaps(tmp_path, monkeypatch):
    from app import gitleaks_runner
    monkeypatch.setenv('GITLEAKS_TIMEOUT_SECONDS', '1')
    monkeypatch.setattr(gitleaks_runner.shutil, 'which', lambda _: sys.executable)
    # Exercise the common process boundary with an actual sleeping child.
    with pytest.raises(subprocess.TimeoutExpired):
        scan_runtime.run_process([sys.executable, '-c', 'import time; time.sleep(30)'],
                                 cwd=tmp_path, env={'PATH': os.defpath}, timeout=0.05)
    assert scan_runtime.timeout_seconds('GITLEAKS_TIMEOUT_SECONDS', 180) == 1
    monkeypatch.setenv('GITLEAKS_TIMEOUT_SECONDS', '0')
    with pytest.raises(ValueError):
        scan_runtime.timeout_seconds('GITLEAKS_TIMEOUT_SECONDS', 180)


def test_store_failure_rolls_back_all_findings(client, worker_db, monkeypatch, tmp_path, capsys):
    scan = project_and_scan(client)
    install_scan_mocks(monkeypatch, tmp_path)
    original = worker.store_results
    def store(data, findings, summaries):
        # Duplicate DB identity deliberately breaks the transaction after normalization.
        original(data, findings + [type(findings[0])(**{
            key: getattr(findings[0], key) for key in ('project_id', 'scan_id', 'scanner', 'category', 'title',
                                                      'severity', 'rule_id', 'fingerprint')})], summaries)
    monkeypatch.setattr(worker, 'store_results', store)
    worker.process_job(worker.claim_job())
    result = client.get('/api/scans').json()[0]
    assert result['status'] == 'FAILED' and result['error_code'] == 'INTERNAL_ERROR'
    assert client.get('/api/findings', params={'scan_id': scan['id']}).json() == []
    assert list(scan_runtime.workspace_root().iterdir()) == []
    assert 'raw-sensitive-value' not in capsys.readouterr().out

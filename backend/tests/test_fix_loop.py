import hashlib
import shutil
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace

import pytest
from app import ai_service as ai
from app import fix_service as fixes
from app import verification, worker
from app.finding_normalizer import normalize_semgrep
from app.models import Category, Fix, Rescan, Scanner
from app.scan_engine import ScannerAdapter
from app.semgrep_runner import SemgrepReport
from sqlalchemy import select
from test_gitleaks import worker_db as worker_db
from test_security_dashboard import finding, project, scan

SOURCE = 'import requests\nresponse = requests.get("https://example.com", verify=False, timeout=10)\n'
PROPOSED = SOURCE.replace('verify=False', 'verify=True')
RULE = 'bultshield.python-tls-verification-disabled'


@pytest.fixture
def setup_fix(client, db, worker_db, monkeypatch, tmp_path):
    settings = SimpleNamespace(ai_enabled=True, ai_model='test', ai_timeout_seconds=10)
    monkeypatch.setattr(fixes, 'get_settings', lambda: settings)
    monkeypatch.setattr(ai, 'get_settings', lambda: settings)
    monkeypatch.setattr(fixes, 'run_gitleaks', lambda p: [])
    monkeypatch.setenv('SCAN_WORKSPACE_ROOT', str(tmp_path / 'jobs'))
    p = project(client)
    s = scan(db, p)
    s.commit_sha = 'a' * 40
    s.scanner_config = {'branch': 'main', 'scanners': ['semgrep']}
    f = finding(db, s, scanner=Scanner.SEMGREP, category=Category.CODE, rule_id=RULE, file='app.py', cve=None)
    db.commit()
    @contextmanager
    def checkout(url, branch, commit=None):
        assert commit == 'a' * 40
        folder = tmp_path / 'checkout'
        folder.mkdir(exist_ok=True)
        (folder / 'app.py').write_text(SOURCE)
        yield folder, commit
    monkeypatch.setattr(fixes, 'checkout_repository', checkout)
    monkeypatch.setattr(verification, 'checkout_repository', checkout)
    monkeypatch.setattr(ai, 'infer', lambda payload, **kw: {'proposed': PROPOSED, 'explanation': 'Включена проверка сертификата TLS без изменения адреса запроса.'})
    def run(path):
        raw = [{'rule_id': RULE, 'file': 'app.py', 'start_line': 2, 'end_line': 2, 'start_col': 1, 'end_col': 90}] if 'verify=False' in (path / 'app.py').read_text() else []
        return SemgrepReport(raw, 1)
    adapter = ScannerAdapter('semgrep', run, normalize_semgrep, RuntimeError, 'test')
    monkeypatch.setattr(verification, 'adapters', lambda: [adapter])
    return f, p, tmp_path, adapter


def test_generation_approval_verification_and_latest_scope(client, db, setup_fix):
    f, p, tmp, _ = setup_fix
    first = client.post(f'/api/findings/{f.id}/fix')
    assert first.status_code == 202
    assert client.post(f'/api/findings/{f.id}/fix').json()['id'] == first.json()['id']
    assert fixes.process_next()
    fix = client.get(f'/api/findings/{f.id}/fix').json()['fix']
    assert fix['status'] == 'PROPOSED' and fix['original'] == SOURCE and fix['proposed'] == PROPOSED
    assert '-response' in fix['diff'] and '+response' in fix['diff']
    result = client.post(f"/api/fixes/{fix['id']}/approve")
    assert result.status_code == 202
    assert client.post(f"/api/fixes/{fix['id']}/approve").json()['verification_scan_id'] == result.json()['verification_scan_id']
    worker.process_job(worker.claim_job())
    final = client.get(f'/api/findings/{f.id}/fix').json()['fix']
    assert final['status'] == 'VERIFIED_FIXED'
    assert final['verification']['before_matches'] == 1 and final['verification']['after_matches'] == 0
    assert not final['verification']['repository_changed']
    assert [entry['status'] for entry in final['timeline']][-4:] == ['APPROVED', 'APPLIED', 'RECHECKING', 'VERIFIED_FIXED']
    assert client.get('/api/security-summary', params={'project_id': p['id']}).json()['total'] == 1
    assert db.scalar(select(Rescan)).outcome == 'VERIFIED_FIXED'
    assert list((tmp / 'jobs').iterdir()) == []


@pytest.mark.parametrize('mode', ['still', 'error', 'missing_before'])
def test_no_false_success(client, db, setup_fix, monkeypatch, mode):
    f, _, _, adapter = setup_fix
    client.post(f'/api/findings/{f.id}/fix')
    fixes.process_next()
    fix = client.get(f'/api/findings/{f.id}/fix').json()['fix']
    client.post(f"/api/fixes/{fix['id']}/approve")
    count = 0
    def run(path):
        nonlocal count
        count += 1
        if mode == 'error' and count > 1:
            raise RuntimeError('raw secret must not be exposed')
        if mode == 'missing_before':
            return SemgrepReport([], 1)
        return SemgrepReport([{'rule_id': RULE, 'file': 'app.py', 'start_line': 7, 'end_line': 7, 'start_col': 1, 'end_col': 90}], 1)
    monkeypatch.setattr(verification, 'adapters', lambda: [ScannerAdapter('semgrep', run, normalize_semgrep, RuntimeError, 'test')])
    worker.process_job(worker.claim_job())
    final = client.get(f'/api/findings/{f.id}/fix').json()['fix']
    assert final['status'] == ('STILL_DETECTED' if mode == 'still' else 'FAILED')
    assert db.scalar(select(Rescan)).outcome == ('STILL_DETECTED' if mode == 'still' else 'INCONCLUSIVE')
    assert 'raw secret' not in str(final)


def test_secret_context_never_reaches_model_or_storage(client, db, setup_fix, monkeypatch):
    f, _, _, _ = setup_fix
    monkeypatch.setattr(fixes, 'run_gitleaks', lambda p: [{'RuleID': 'secret'}])
    monkeypatch.setattr(ai, 'infer', lambda *a, **kw: pytest.fail('Secret reached model'))
    client.post(f'/api/findings/{f.id}/fix')
    fixes.process_next()
    fix = client.get(f'/api/findings/{f.id}/fix').json()['fix']
    assert fix['status'] == 'FAILED' and fix['original'] is None and fix['proposed'] is None
    assert client.post(f"/api/fixes/{fix['id']}/approve").status_code == 409


def test_source_path_size_and_symlink(tmp_path):
    (tmp_path / 'source.py').write_text(SOURCE)
    for name in ['../escape.py', '/etc/passwd', '.git/config']:
        with pytest.raises(fixes.FixError):
            fixes.source_file(tmp_path, name)
    (tmp_path / 'link.py').symlink_to(tmp_path / 'source.py')
    with pytest.raises(fixes.FixError):
        fixes.source_file(tmp_path, 'link.py')
    (tmp_path / 'big.py').write_text('a' * 4097)
    with pytest.raises(fixes.FixError):
        fixes.source_file(tmp_path, 'big.py')


def test_patch_guards(monkeypatch):
    monkeypatch.setattr(fixes, 'run_gitleaks', lambda p: [])
    for after in ['', SOURCE, 'broken Python $$$\n', SOURCE + '# nosemgrep\n']:
        with pytest.raises(fixes.FixError):
            fixes.validate_proposal(SOURCE, after, 'app.py')
    with pytest.raises(fixes.FixError):
        fixes.check_secrets('password = "not-a-real-test-password"')


def test_missing_import_is_rejected_without_running_source(monkeypatch):
    monkeypatch.setattr(fixes, 'run_gitleaks', lambda p: [])
    original = 'def parse(text):\n    return eval(text)\n'
    missing_import = original.replace('eval(text)', 'json.loads(text)')
    with pytest.raises(fixes.FixError, match='неопределённое имя'):
        fixes.validate_proposal(original, missing_import, 'app.py')
    fixes.validate_proposal(original, 'import json\n' + missing_import, 'app.py')
    fixes.validate_proposal(original, missing_import.replace('    return', '    import json\n    return'), 'app.py')


def test_rejected_proposal_can_be_regenerated_but_not_approved(client, db, setup_fix):
    f, _, _, _ = setup_fix
    first = client.post(f'/api/findings/{f.id}/fix').json()
    fixes.process_next()
    rejected = client.post(f"/api/fixes/{first['id']}/reject")
    assert rejected.status_code == 200 and rejected.json()['status'] == 'FAILED'
    assert client.post(f"/api/fixes/{first['id']}/approve").status_code == 409
    second = client.post(f'/api/findings/{f.id}/fix').json()
    assert second['id'] != first['id']
    fixes.process_next()
    assert client.post(f"/api/fixes/{second['id']}/approve").status_code == 202
    assert client.post(f"/api/fixes/{second['id']}/reject").status_code == 409


def test_hash_mismatch_and_stale_worker_never_verify(client, db, setup_fix):
    f, _, _, _ = setup_fix
    client.post(f'/api/findings/{f.id}/fix')
    fixes.process_next()
    record = db.scalar(select(Fix))
    record.original_hash = hashlib.sha256(b'changed').hexdigest()
    db.commit()
    client.post(f'/api/fixes/{record.id}/approve')
    worker.process_job(worker.claim_job())
    assert client.get(f'/api/findings/{f.id}/fix').json()['fix']['verification']['outcome'] == 'INCONCLUSIVE'


def test_verification_worker_loss_is_inconclusive(client, db, setup_fix):
    f, _, _, _ = setup_fix
    client.post(f'/api/findings/{f.id}/fix')
    fixes.process_next()
    record = db.scalar(select(Fix))
    client.post(f'/api/fixes/{record.id}/approve')
    data = worker.claim_job()
    from app.models import ScanJob
    job = db.get(ScanJob, data.job_id)
    job.heartbeat_at = ai.now() - timedelta(minutes=10)
    db.commit()
    worker.recover_stale_jobs()
    assert client.get(f'/api/findings/{f.id}/fix').json()['fix']['status'] == 'FAILED'
    db.expire_all()
    assert db.scalar(select(Rescan)).outcome == 'INCONCLUSIVE'


@pytest.mark.skipif(not shutil.which('semgrep'), reason='Pinned Semgrep CLI not installed')
def test_real_semgrep_verification_loop(client, db, setup_fix, monkeypatch):
    from app.semgrep_runner import SemgrepError, run_semgrep
    f, _, _, _ = setup_fix
    monkeypatch.setattr(verification, 'adapters', lambda: [ScannerAdapter('semgrep', run_semgrep, normalize_semgrep, SemgrepError, '1.178.0')])
    client.post(f'/api/findings/{f.id}/fix')
    fixes.process_next()
    record = db.scalar(select(Fix))
    assert record.status == 'PROPOSED'
    client.post(f'/api/fixes/{record.id}/approve')
    worker.process_job(worker.claim_job())
    final = client.get(f'/api/findings/{f.id}/fix').json()['fix']
    assert final['status'] == 'VERIFIED_FIXED', final['error_message']
    assert final['verification']['before_matches'] == 1
    assert final['verification']['after_matches'] == 0

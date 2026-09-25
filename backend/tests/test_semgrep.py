import copy
import json
import shutil
import subprocess
from contextlib import contextmanager
from uuid import UUID

import pytest
from app import scan_engine, worker
from app.gitleaks_runner import GitleaksError
from app.models import ScanJob
from app.scanner_catalog import RULES, SEMGREP_VERSION
from app.semgrep_runner import SemgrepError, SemgrepReport, _run, _snapshot, parse_semgrep_report, run_semgrep
from test_gitleaks import project_and_scan, sanitized
from test_gitleaks import worker_db as worker_db


def raw_report(root):
    (root / 'demo.py').write_text('eval(value)\n')
    return {
        'version': SEMGREP_VERSION, 'errors': [], 'paths': {'scanned': ['demo.py']},
        'results': [{
            'check_id': 'bultshield.python-dynamic-eval', 'path': 'demo.py',
            'start': {'line': 1, 'col': 1}, 'end': {'line': 1, 'col': 12},
            'extra': {'lines': 'SENSITIVE_SOURCE', 'message': 'SENSITIVE_SOURCE',
                      'metavars': {'$VALUE': 'SENSITIVE_SOURCE'}, 'fix': 'SENSITIVE_SOURCE'},
        }],
    }


def test_parser_discards_source_and_interpolated_fields(tmp_path):
    result = parse_semgrep_report(raw_report(tmp_path), tmp_path, 1)
    assert result.scanned_files == 1
    assert 'SENSITIVE_SOURCE' not in json.dumps(result.findings)
    assert set(result.findings[0]) == {'rule_id', 'file', 'start_line', 'end_line', 'start_col', 'end_col'}


@pytest.mark.parametrize('mutation', [
    lambda r: r.update(errors=[{'message': 'SENSITIVE_SOURCE'}]),
    lambda r: r.update(version='0.0.0'),
    lambda r: r.update(results={}),
    lambda r: r.update(paths={'scanned': []}),
    lambda r: r['results'][0].update(check_id='repo-controlled-rule'),
    lambda r: r['results'][0].update(path='../outside.py'),
    lambda r: r['results'][0].update(start={'line': True, 'col': 1}),
    lambda r: r['results'][0].update(end={'line': 0, 'col': 1}),
    lambda r: r['results'][0].update(end={'line': 1, 'col': 0}),
    lambda r: r['results'][0].update(start={'line': 2, 'col': 1}),
    lambda r: r['results'][0].update(end={'line': 2**32, 'col': 1}),
])
def test_parser_rejects_incomplete_or_invalid_report(tmp_path, mutation):
    data = raw_report(tmp_path)
    mutation(data)
    with pytest.raises(SemgrepError) as result:
        parse_semgrep_report(data, tmp_path, 1)
    assert 'SENSITIVE_SOURCE' not in str(result.value)


def test_snapshot_ignores_repo_config_and_symlinks(tmp_path):
    source = tmp_path / 'repo'
    source.mkdir()
    (source / 'test.py').write_text('eval(value)')
    (source / '.semgrepignore').write_text('*')
    (source / '.gitignore').write_text('*')
    (source / 'sub').mkdir()
    (source / 'sub' / '.semgrepignore').write_text('*')
    (source / 'sub' / 'test.ts').write_text('eval(value)')
    (source / 'outside.py').symlink_to('/etc/passwd')
    (source / 'vendor').mkdir()
    (source / 'vendor' / 'x.py').write_text('eval(value)')
    target = tmp_path / 'snapshot'
    assert _snapshot(source, target) == 2
    assert (target / '.semgrepignore').read_text() == ''
    assert not (target / 'outside.py').exists()
    assert not (target / 'sub' / '.semgrepignore').exists()
    assert not (target / '.gitignore').exists()


def test_runner_does_not_inherit_credentials_or_enable_cloud(tmp_path, monkeypatch):
    from app import semgrep_runner
    (tmp_path / 'demo.py').write_text('eval(value)\n')
    monkeypatch.setenv('DATABASE_URL', 'SENSITIVE_SOURCE')
    monkeypatch.setenv('SEMGREP_APP_TOKEN', 'SENSITIVE_SOURCE')
    monkeypatch.setattr(semgrep_runner.shutil, 'which', lambda name: '/opt/semgrep/bin/semgrep')
    def run(command, snapshot, env):
        assert 'SENSITIVE_SOURCE' not in json.dumps(env)
        assert '--oss-only' in command and '--metrics=off' in command and '--disable-version-check' in command
        assert '--disable-nosem' in command and '--no-autofix' in command
        report = command[command.index('--output') + 1]
        from pathlib import Path
        Path(report).write_text(json.dumps(raw_report(snapshot)))
        return 0
    monkeypatch.setattr(semgrep_runner, '_run', run)
    assert len(run_semgrep(tmp_path).findings) == 1


def test_timeout_kills_process_group(monkeypatch, tmp_path):
    from app import semgrep_runner
    killed = []
    class Process:
        pid = 123
        def wait(self, timeout=None):
            if timeout is not None:
                raise subprocess.TimeoutExpired('semgrep', timeout)
            return -9
    monkeypatch.setattr(semgrep_runner.subprocess, 'Popen', lambda *a, **kw: Process())
    monkeypatch.setattr(semgrep_runner.os, 'killpg', lambda pid, sig: killed.append(pid))
    with pytest.raises(SemgrepError, match='лимит времени'):
        _run([], tmp_path, {})
    assert killed == [123]


def install_scan_mocks(monkeypatch, tmp_path):
    @contextmanager
    def checkout(url, branch):
        yield tmp_path, 'b' * 40
    monkeypatch.setattr(scan_engine, 'checkout_repository', checkout)
    semgrep = parse_semgrep_report(raw_report(tmp_path), tmp_path, 1)
    gitleaks = sanitized(tmp_path)
    gitleaks['File'] = 'demo.py'  # Same file and line, different scanners.
    monkeypatch.setattr(scan_engine, 'run_gitleaks', lambda path: [gitleaks, copy.deepcopy(gitleaks)])
    monkeypatch.setattr(scan_engine, 'run_semgrep', lambda path: SemgrepReport(semgrep.findings * 2, 1))


def test_combined_findings_duplicates_repeated_scans_and_filters(client, worker_db, monkeypatch, tmp_path):
    scan = project_and_scan(client)
    assert scan['scanner_config']['scanners'] == ['gitleaks', 'semgrep', 'trivy']
    install_scan_mocks(monkeypatch, tmp_path)
    job = worker.claim_job()
    worker.process_job(job)
    worker.process_job(job)  # Old claimed job cannot insert results twice.
    results = client.get('/api/findings', params={'scan_id': scan['id']}).json()
    assert len(results) == 2
    assert {f['scanner'] for f in results} == {'gitleaks', 'semgrep'}
    assert len({f['fingerprint'] for f in results}) == 2
    assert all(f['evidence'] == '[REDACTED]' for f in results)
    assert 'SENSITIVE_SOURCE' not in json.dumps(results)
    assert len(client.get('/api/findings?scanner=semgrep').json()) == 1
    assert len(client.get('/api/findings?scanner=gitleaks').json()) == 1
    semgrep = next(f for f in results if f['scanner'] == 'semgrep')
    assert (semgrep['severity'], semgrep['original_severity'], semgrep['cwe']) == ('HIGH', 'ERROR', 'CWE-95')
    assert client.get('/api/scans').json()[0]['status'] == 'COMPLETED'
    again = client.post('/api/scans', json={'repository_id': scan['repository_id']}).json()
    worker.process_job(worker.claim_job())
    later = client.get('/api/findings', params={'scan_id': again['id']}).json()
    assert len(later) == 2
    assert {f['fingerprint'] for f in later} == {f['fingerprint'] for f in results}


@pytest.mark.parametrize('failed_scanner', ['gitleaks', 'semgrep'])
def test_partial_failure_preserves_successful_scanner(client, worker_db, monkeypatch, tmp_path, failed_scanner):
    scan = project_and_scan(client)
    install_scan_mocks(monkeypatch, tmp_path)
    def fail(path):
        raise (GitleaksError if failed_scanner == 'gitleaks' else SemgrepError)('Безопасная ошибка сканера.')
    monkeypatch.setattr(scan_engine, f'run_{failed_scanner}', fail)
    worker.process_job(worker.claim_job())
    result = client.get('/api/scans').json()[0]
    assert result['status'] == 'FAILED'
    assert result['scanner_results'][failed_scanner]['status'] == 'FAILED'
    other = 'semgrep' if failed_scanner == 'gitleaks' else 'gitleaks'
    assert result['scanner_results'][other]['status'] == 'COMPLETED'
    findings = client.get('/api/findings', params={'scan_id': scan['id']}).json()
    assert len(findings) == 1 and findings[0]['scanner'] == other


def test_worker_crash_before_store_is_atomic(client, db, worker_db, monkeypatch, tmp_path):
    scan = project_and_scan(client)
    install_scan_mocks(monkeypatch, tmp_path)
    def crash(path):
        raise RuntimeError('SENSITIVE_SOURCE')
    monkeypatch.setattr(scan_engine, 'run_semgrep', crash)
    job = worker.claim_job()
    worker.process_job(job)
    result = client.get('/api/scans').json()[0]
    assert result['status'] == 'FAILED'
    assert result['scanner_results']['gitleaks']['status'] == 'FAILED'
    assert result['scanner_results']['semgrep']['status'] == 'FAILED'
    assert 'SENSITIVE_SOURCE' not in json.dumps(result)
    assert client.get('/api/findings', params={'scan_id': scan['id']}).json() == []
    assert db.get(ScanJob, UUID(str(job.job_id))).status == 'FAILED'


@pytest.mark.skipif(shutil.which('semgrep') is None, reason='Real CLI runs in worker container and CI')
def test_real_semgrep_rules_clean_positive_and_ignores(tmp_path):
    (tmp_path / 'safe.py').write_text('import json\nimport subprocess\nimport yaml\njson.loads(value)\nsubprocess.run(["echo", value], shell=False)\nyaml.safe_load(value)\n')
    (tmp_path / 'safe.ts').write_text('JSON.parse(value);\nelement.textContent = value;\n')
    assert run_semgrep(tmp_path).findings == []
    (tmp_path / 'unsafe.py').write_text('''import subprocess, pickle, yaml, requests
# rule patterns are never executed by this test
eval(value)  # nosemgrep
subprocess.run(value, shell=True)
pickle.loads(value)
yaml.unsafe_load(value)
requests.get(url, verify=False)
''')
    (tmp_path / 'tests').mkdir()
    (tmp_path / 'tests' / 'unsafe.ts').write_text('''eval(value); // nosemgrep
require("child_process").exec(value);
element.innerHTML = value;
''')
    (tmp_path / '.semgrepignore').write_text('*\n')
    (tmp_path / '.gitignore').write_text('*\n')
    (tmp_path / 'tests' / '.semgrepignore').write_text('*\n')
    report = run_semgrep(tmp_path)
    assert report.scanned_files == 4
    assert {f['rule_id'] for f in report.findings} == set(RULES)
    assert len(report.findings) == len(RULES)
    assert all(f['file'].startswith(('unsafe.py', 'tests/unsafe.ts')) for f in report.findings)
    assert (tmp_path / 'unsafe.py').read_text().endswith('requests.get(url, verify=False)\n')
    (tmp_path / 'broken.py').write_text('eval(\n')
    with pytest.raises(SemgrepError):
        run_semgrep(tmp_path)

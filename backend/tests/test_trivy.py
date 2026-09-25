import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from app import scan_engine, trivy_runner, worker
from app.finding_normalizer import normalize_trivy
from app.models import Finding, FindingStatus, ScanJob
from app.trivy_runner import TrivyError, TrivyReport, _run, _snapshot, parse_trivy_report, run_trivy
from test_gitleaks import project_and_scan
from test_gitleaks import worker_db as worker_db
from test_semgrep import install_scan_mocks


def raw_report():
    return {'SchemaVersion': 2, 'Trivy': {'Version': '0.74.0'}, 'ArtifactType': 'filesystem', 'Results': [
        {'Target': 'requirements.txt', 'Class': 'lang-pkgs', 'Type': 'pip', 'Vulnerabilities': [
            {'VulnerabilityID': 'CVE-2024-12345', 'PkgName': 'demo', 'PkgID': 'demo@1.0',
             'InstalledVersion': '1.0', 'FixedVersion': '1.1, 2.0', 'Severity': 'HIGH',
             'Description': 'PRIVATE_SOURCE', 'References': ['PRIVATE_SOURCE']}]},
        {'Target': 'Dockerfile', 'Class': 'config', 'Type': 'dockerfile', 'Misconfigurations': [
            {'ID': 'DS-0002', 'Severity': 'HIGH', 'Status': 'FAIL', 'Title': 'PRIVATE_SOURCE',
             'Message': 'PRIVATE_SOURCE', 'CauseMetadata': {'StartLine': 1, 'EndLine': 2,
                                                         'Code': {'Lines': ['PRIVATE_SOURCE']}}}]},
    ]}


def parse(data=None):
    return parse_trivy_report(data or raw_report(), {'requirements.txt', 'Dockerfile'})


def test_parser_maps_versions_categories_and_redacts():
    report = parse()
    assert len(report.findings) == 2
    dep, config = report.findings
    assert (dep['cve'], dep['package'], dep['installed_version'], dep['fixed_version']) == ('CVE-2024-12345', 'demo', '1.0', '1.1, 2.0')
    assert config['category'] == 'configuration' and config['line_end'] == 2
    assert 'PRIVATE_SOURCE' not in json.dumps(report.findings)


@pytest.mark.parametrize('change', [
    lambda d: d.update(SchemaVersion=1), lambda d: d.update(Trivy={'Version': '0.0.0'}), lambda d: d.update(ArtifactType='container_image'),
    lambda d: d.update(Results='invalid'), lambda d: d['Results'][0].update(Target='../requirements.txt'),
    lambda d: d['Results'][0].update(Target='/etc/passwd'), lambda d: d['Results'][0].update(Class='os-pkgs'),
    lambda d: d['Results'][0]['Vulnerabilities'][0].update(Severity='NEW'),
    lambda d: d['Results'][0]['Vulnerabilities'][0].update(PkgName='x'*513),
    lambda d: d['Results'][0]['Vulnerabilities'][0].update(InstalledVersion='1\n2'),
    lambda d: d['Results'][0]['Vulnerabilities'][0].update(VulnerabilityID='../../secret'),
    lambda d: d['Results'][1]['Misconfigurations'][0].update(Status='UNKNOWN'),
    lambda d: d['Results'][1]['Misconfigurations'][0].update(CauseMetadata={'StartLine': True}),
    lambda d: d['Results'][1]['Misconfigurations'][0].update(CauseMetadata={'StartLine': 3, 'EndLine': 2}),
])
def test_reject_invalid_report(change):
    data = raw_report()
    change(data)
    with pytest.raises(TrivyError):
        parse(data)


def test_no_cve_no_fix_unknown_severity_and_inline_exceptions():
    data = raw_report()
    data['Results'][0]['Vulnerabilities'][0].update(VulnerabilityID='GHSA-abcd-abcd-abcd', FixedVersion='', Severity='UNKNOWN')
    data['Results'][1]['Misconfigurations'][0]['Status'] = 'EXCEPTION'
    result = parse(data).findings
    assert result[0]['cve'] is None and result[0]['fixed_version'] is None
    assert result[0]['severity'] == 'UNKNOWN' and result[1]['suppressed'] is True
    data['Results'][1]['Misconfigurations'][0]['Status'] = 'PASS'
    assert len(parse(data).findings) == 1
    assert parse_trivy_report({'SchemaVersion': 2, 'Trivy': {'Version': '0.74.0'}, 'ArtifactType': 'filesystem'}, set()).findings == []


def test_snapshot_excludes_untrusted_policy_and_binaries(tmp_path):
    source, target = tmp_path/'repo', tmp_path/'snapshot'
    source.mkdir()
    for name in ['requirements-dev.txt', 'package-lock.json', 'Dockerfile.worker', 'main.tf', 'pod.yaml',
                 '.trivyignore', 'trivy.yaml', 'custom.rego', 'app.jar', 'script.py']:
        (source/name).write_text('content')
    (source/'requirements.txt').symlink_to('/etc/passwd')
    (source/'node_modules').mkdir()
    (source/'node_modules'/'package-lock.json').write_text('content')
    assert _snapshot(source, target) == {'requirements-dev.txt', 'package-lock.json', 'Dockerfile.worker', 'pod.yaml'}


def test_combined_three_scanners_and_server_filters(client, db, worker_db, monkeypatch, tmp_path):
    scan = project_and_scan(client)
    install_scan_mocks(monkeypatch, tmp_path)
    report = parse()
    # Duplicate identical reports collapse, different versions and scanners survive.
    other = {**report.findings[0], 'installed_version': '0.9', 'package_id': 'demo@0.9', 'fixed_version': None}
    monkeypatch.setattr(scan_engine, 'run_trivy', lambda p: TrivyReport(report.findings * 2 + [other], {}))
    worker.process_job(worker.claim_job())
    results = client.get('/api/findings', params={'scan_id': scan['id']}).json()
    assert len(results) == 5 and {f['scanner'] for f in results} == {'trivy', 'gitleaks', 'semgrep'}
    assert len({f['fingerprint'] for f in results}) == 5
    assert all(f['evidence'] == '[REDACTED]' for f in results)
    assert 'PRIVATE_SOURCE' not in json.dumps(results)
    assert client.get('/api/scans').json()[0]['status'] == 'COMPLETED'
    query = {'scan_id': scan['id'], 'scanner': 'trivy', 'category': 'dependency', 'severity': 'HIGH', 'status': 'OPEN'}
    assert len(client.get('/api/findings', params=query).json()) == 2
    first = db.query(Finding).filter(Finding.scanner == 'trivy', Finding.category == 'dependency').first()
    first.status = FindingStatus.VERIFIED_FIXED
    db.commit()
    assert len(client.get('/api/findings', params=query).json()) == 1
    query['status'] = 'VERIFIED_FIXED'
    assert len(client.get('/api/findings', params=query).json()) == 1
    assert client.get('/api/findings?category=invalid').status_code == 422
    again = client.post('/api/scans', json={'repository_id': scan['repository_id']}).json()
    worker.process_job(worker.claim_job())
    later = client.get('/api/findings', params={'scan_id': again['id']}).json()
    assert {f['fingerprint'] for f in later} == {f['fingerprint'] for f in results}


def test_filters_applied_before_limit(client, db):
    from uuid import UUID
    scan = project_and_scan(client)
    findings = normalize_trivy(parse().findings, project_id=UUID(scan['project_id']), repository_id=UUID(scan['repository_id']),
                               scan_id=UUID(scan['id']), commit_sha='a'*40)
    db.add_all(findings)
    db.commit()
    # Newer nonmatching data must not hide a matching older row when limit=1.
    findings[1].created_at = datetime.now(timezone.utc) + timedelta(seconds=5)
    db.commit()
    data = client.get('/api/findings?category=dependency&limit=1').json()
    assert len(data) == 1 and data[0]['category'] == 'dependency'


def test_trivy_failure_preserves_other_scanners(client, worker_db, monkeypatch, tmp_path):
    scan = project_and_scan(client)
    install_scan_mocks(monkeypatch, tmp_path)
    def fail(path):
        raise TrivyError('База CVE недоступна.')
    monkeypatch.setattr(scan_engine, 'run_trivy', fail)
    worker.process_job(worker.claim_job())
    result = client.get('/api/scans').json()[0]
    assert result['status'] == 'FAILED' and result['scanner_results']['trivy']['status'] == 'FAILED'
    assert {f['scanner'] for f in client.get('/api/findings', params={'scan_id': scan['id']}).json()} == {'gitleaks', 'semgrep'}


@pytest.mark.parametrize('stale', [False, True])
def test_runner_environment_policy_and_stale_db(tmp_path, monkeypatch, stale):
    repo, home = tmp_path/'repo', tmp_path/'home'
    repo.mkdir()
    (repo/'requirements.txt').write_text('demo==1.0')
    monkeypatch.setattr(Path, 'home', lambda: home)
    monkeypatch.setenv('DATABASE_URL', 'PRIVATE_SOURCE')
    monkeypatch.setenv('TRIVY_TOKEN', 'PRIVATE_SOURCE')
    monkeypatch.setenv('TRIVY_CONFIG', 'PRIVATE_SOURCE')
    monkeypatch.setattr(trivy_runner.shutil, 'which', lambda name: '/usr/local/bin/trivy')
    calls = []
    def run(command, cwd, env, log, report=None, timeout=300):
        assert 'PRIVATE_SOURCE' not in json.dumps(env)
        assert cwd.parent == home / '.cache' / 'bultshield-trivy'
        assert env['TMPDIR'] == str(cwd)
        assert '--disable-telemetry' in command
        calls.append(command)
        if '--download-db-only' in command:
            assert str(repo) not in command and not (cwd/'requirements.txt').exists()
            cache = Path(command[command.index('--cache-dir')+1])/'db'
            cache.mkdir()
            (cache/'metadata.json').write_text(json.dumps({'UpdatedAt': (datetime.now(timezone.utc)-timedelta(days=2 if stale else 0)).isoformat()}))
        else:
            assert '--offline-scan' in command and '--skip-db-update' in command
            assert '--ignorefile' in command and '--skip-check-update' in command
            data = raw_report()
            data['Results'] = data['Results'][:1]
            report.write_text(json.dumps(data))
    monkeypatch.setattr(trivy_runner, '_run', run)
    if stale:
        with pytest.raises(TrivyError):
            run_trivy(repo)
        assert len(calls) == 1
    else:
        assert len(run_trivy(repo).findings) == 1
        assert len(calls) == 2


def test_timeout_kills_process_group(tmp_path, monkeypatch):
    monkeypatch.setattr(trivy_runner, '_prefer_child_oom_victim', lambda pid: None)
    killed = []
    class Process:
        pid = 123
        def poll(self):
            return None
        def wait(self):
            return -9
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **kw: Process())
    monkeypatch.setattr(trivy_runner.os, 'killpg', lambda pid, sig: killed.append(pid))
    with pytest.raises(TrivyError):
        _run([], tmp_path, {}, tmp_path/'log', timeout=0)
    assert killed == [123]


@pytest.mark.skipif(shutil.which('trivy') is None, reason='Real CLI runs in worker container and CI')
def test_real_trivy_dependencies_config_and_ignores(tmp_path, monkeypatch):
    # Only this synthetic fixture may expose diagnostic logs on failure, never production scans.
    real_run = trivy_runner._run
    def fixture_run(command, cwd, environment, log, report=None, timeout=300):
        try:
            return real_run(command, cwd, environment, log, report, timeout)
        except TrivyError as exc:
            pytest.fail(f"Synthetic Trivy fixture: {exc}\n{log.read_text()[-5000:]}")
    monkeypatch.setattr(trivy_runner, '_run', fixture_run)
    (tmp_path/'requirements.txt').write_text('django==2.2.0\n')
    (tmp_path/'Dockerfile').write_text('FROM alpine:latest\n#trivy:ignore:DS-0002\nUSER root\n')
    (tmp_path/'pod.yaml').write_text('apiVersion: v1\nkind: Pod\nmetadata:\n  name: scanner-fixture\nspec:\n  containers:\n    - name: app\n      image: nginx:latest\n      securityContext:\n        privileged: true\n')
    (tmp_path/'.trivyignore').write_text('DS-0002\nDS-0001\n*\n')
    (tmp_path/'trivy.yaml').write_text('scanners: []\nseverity: [UNKNOWN]\n')
    report = run_trivy(tmp_path)
    dependencies = [f for f in report.findings if f['category'] == 'dependency']
    configs = [f for f in report.findings if f['category'] == 'configuration']
    assert dependencies and configs
    assert any(f['cve'] and f['package'] == 'django' and f['fixed_version'] for f in dependencies)
    assert any(f['rule_id'] == 'DS-0002' for f in configs)
    assert any(f['ecosystem'] == 'kubernetes' for f in configs)
    assert report.summary['db_updated_at']
    (tmp_path/'pod.yaml').unlink()
    (tmp_path/'requirements.txt').unlink()
    (tmp_path/'Dockerfile').unlink()
    assert run_trivy(tmp_path).findings == []


def test_snapshot_disables_full_line_ignores_and_rejects_inline(tmp_path):
    repo = tmp_path/'repo'
    repo.mkdir()
    (repo/'Dockerfile').write_text('FROM alpine:3.22\n#trivy:ignore:DS-0002\nUSER root\n')
    target = tmp_path/'copy'
    _snapshot(repo, target)
    assert 'trivy:ignore' not in (target/'Dockerfile').read_text()
    assert (target/'Dockerfile').read_text().splitlines()[2] == 'USER root'
    assert 'trivy:ignore' in (repo/'Dockerfile').read_text()
    (repo/'pod.yaml').write_text('privileged: true #trivy:ignore:KSV001\n')
    with pytest.raises(TrivyError):
        _snapshot(repo, tmp_path/'other')


@pytest.mark.parametrize('message, fails', [
    (b'2026-01-01\tERROR\t[misconfig] Falling back to embedded checks\terr="cache does not exist at x"', False),
    (b'2026-01-01\tWARN\t[pip] Unable to find python `site-packages` directory. License detection is skipped.', False),
    (b'2026-01-01\tWARN\t[kubernetes] Failed to parse YAML', True),
    (b'2026-01-01\tERROR\t[vuln] Failed to load database', True),
])
def test_diagnostics_allow_only_expected_non_scan_failures(tmp_path, monkeypatch, message, fails):
    class Process:
        returncode = 0
        def poll(self):
            return 0
    def popen(*args, **kwargs):
        kwargs['stdout'].write(message)
        kwargs['stdout'].flush()
        return Process()
    monkeypatch.setattr(subprocess, 'Popen', popen)
    if fails:
        with pytest.raises(TrivyError):
            _run([], tmp_path, {}, tmp_path/'log')
    else:
        _run([], tmp_path, {}, tmp_path/'log')


@pytest.mark.parametrize('returncode', [0, 1])
def test_database_mirror_fallback_requires_successful_exit(tmp_path, monkeypatch, returncode):
    class Process:
        def poll(self):
            return returncode
    process = Process()
    process.returncode = returncode
    def popen(*args, **kwargs):
        kwargs['stdout'].write(b'ERROR first mirror unavailable\nINFO alternate mirror downloaded\n')
        kwargs['stdout'].flush()
        return process
    monkeypatch.setattr(subprocess, 'Popen', popen)
    if returncode:
        with pytest.raises(TrivyError):
            _run(['trivy', 'fs', '--download-db-only'], tmp_path, {}, tmp_path/'log')
    else:
        _run(['trivy', 'fs', '--download-db-only'], tmp_path, {}, tmp_path/'log')


def test_restart_before_store_publishes_no_findings(client, db, worker_db, monkeypatch, tmp_path):
    scan = project_and_scan(client)
    install_scan_mocks(monkeypatch, tmp_path)
    def interrupted(path):
        raise SystemExit('simulated worker termination')
    monkeypatch.setattr(scan_engine, 'run_trivy', interrupted)
    data = worker.claim_job()
    with pytest.raises(SystemExit):
        worker.process_job(data)
    job = db.get(ScanJob, data.job_id)
    job.heartbeat_at = datetime.now(timezone.utc) - timedelta(minutes=16)
    db.commit()
    worker.recover_stale_jobs()
    result = client.get('/api/scans').json()[0]
    assert result['status'] == 'FAILED'
    assert result['scanner_results']['trivy']['status'] == 'FAILED'
    assert all(result['scanner_results'][name]['status'] == 'FAILED' for name in ('gitleaks', 'semgrep'))
    assert client.get('/api/findings', params={'scan_id': scan['id']}).json() == []
    assert client.post('/api/scans', json={'repository_id': scan['repository_id']}).status_code == 202


def test_download_cache_release_is_scoped_and_keeps_files(tmp_path, monkeypatch):
    owned = tmp_path / 'cache'
    owned.mkdir()
    database = owned / 'db'
    database.write_bytes(b'x' * (1024 * 1024))
    outside = tmp_path / 'outside'
    outside.write_bytes(b'x' * (1024 * 1024))
    (owned / 'link').symlink_to(outside)
    released = []
    monkeypatch.setattr(trivy_runner.os, 'posix_fadvise', lambda *args: released.append(args), raising=False)
    monkeypatch.setattr(trivy_runner.os, 'POSIX_FADV_DONTNEED', 4, raising=False)
    monkeypatch.setattr(trivy_runner.os, 'fdatasync', lambda fd: None, raising=False)
    trivy_runner._release_download_cache([owned])
    assert len(released) == 1
    assert database.exists() and outside.exists()

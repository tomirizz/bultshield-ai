import subprocess
import uuid
from datetime import timedelta

import pytest
from app import fix_runs, image_pipeline, worker
from app.check_report import STATUS_TEXT, load_report
from app.fix_agent import FIX_PASSED, FIX_PROPOSED, MANUAL, AgentResult, PackageItem
from app.fix_runs import FixRunError, complete_run, create_run, effective_status, findings_for_agent, run_agent_for_scan
from app.image_scan import ImageScanError
from app.models import DependencyFixRun, Finding, Project, Repository, Scan, ScanStatus
from app.tenant import isolate
from sqlalchemy import select
from sqlalchemy.orm import Session
from test_gitleaks import worker_db as worker_db
from test_image_jobs import DIGEST, FIXTURE, REFERENCE, create_image_scan, repository, scan_result  # noqa: F401

COMMIT = 'aa7759883f250c81139e7f2a28bba00cf73c6246'
LODASH_RULES = ['CVE-2020-28500', 'CVE-2020-8203', 'CVE-2021-23337', 'CVE-2025-13465', 'CVE-2026-2950', 'CVE-2026-4800', 'NSWG-ECO-516']
COMBINED_OK = {'packages': ['lodash'], 'outcome': 'FIX_VERIFIED', 'reason': 'Тесты, сборка и запуск прошли.',
               'scan_db_updated_at': '2026-10-07T07:38:55Z'}


@pytest.fixture(autouse=True)
def allow_local_registry(monkeypatch):
    monkeypatch.setenv('IMAGE_ALLOWED_REGISTRIES', 'localhost:5001')


@pytest.fixture
def check(client, db, worker_db, monkeypatch):
    """Завершённая проверка образа с 14 находками: 7 в lodash приложения и 7 вне приложения."""
    scan = create_image_scan(db, repository(client), REFERENCE)
    monkeypatch.setattr(image_pipeline, 'run_image_scan', lambda reference: scan_result())
    worker.process_job(worker.claim_job())
    return scan.id


def item(status=FIX_PASSED, needs_review=False, reason='Тесты, сборка и запуск прошли.', target='4.18.1', package='lodash'):
    return PackageItem(package, '4.17.15', list(LODASH_RULES), status, reason, target=target, needs_review=needs_review,
                       plan={'status': 'PROPOSE'},
                       verification={'outcome': 'FIX_VERIFIED', 'reason': reason, 'diff': '--- a\n+++ b\n', 'method': 'direct',
                                     'steps': [{'name': 'tests', 'status': 'passed', 'seconds': 1, 'log_tail': 'ok'}]})


def agent_returning(items, combined=COMBINED_OK):
    def agent(project_dir, findings, **kwargs):
        agent.calls.append((project_dir, findings, kwargs))
        return AgentResult(items, [], {'packages': len(items)}, combined=combined)
    agent.calls = []
    return agent


def states(report):
    return {i['rule_id']: i['status'] for i in report['findings']['items'] if i['origin'] == 'app'}


def report_of(db, scan_id):
    return load_report(db, db.get(Scan, scan_id), limit=500)


def test_findings_for_agent_match_the_report_parser(db, check):
    import json

    from app.image_report import parse_image_report
    parsed = parse_image_report(json.loads(FIXTURE.read_text())).findings
    rows = db.scalars(select(Finding).where(Finding.scan_id == check)).all()
    key = lambda f: (f['rule_id'], f['package'], f['installed_version'], f['file'])  # noqa: E731
    assert sorted(findings_for_agent(rows), key=key) == sorted(parsed, key=key)


def test_run_is_saved_with_digest_commit_and_linked_findings(db, check):
    agent = agent_returning([item()])
    run = run_agent_for_scan(db, check, '/nonexistent', commit_sha=COMMIT, agent=agent)
    saved = db.get(DependencyFixRun, run.id)
    assert saved.status == 'COMPLETED' and saved.image_digest == DIGEST and saved.commit_sha == COMMIT
    assert len(saved.items) == 1 and len(saved.items[0]['finding_ids']) == 7
    assert sorted(saved.items[0]['rule_ids']) == LODASH_RULES
    linked = {f.id for f in db.scalars(select(Finding).where(Finding.id.in_(saved.items[0]['finding_ids'])))}
    assert len(linked) == 7 and all(f.extra['package'] == 'lodash' for f in db.scalars(select(Finding).where(Finding.id.in_(linked))))
    # агент получил именно находки этой проверки
    assert len(agent.calls[0][1]) == 14


def test_verified_fix_is_shown_but_never_as_deployed(db, check):
    run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item()]))
    report = report_of(db, check)
    assert set(states(report).values()) == {'FIX_VERIFIED'}
    assert report['facts']['by_status'] == {'FIX_VERIFIED': 7, 'MANUAL_REVIEW': 7}
    assert 'FIX_DEPLOYED' not in report['facts']['by_status']
    shown = next(i for i in report['findings']['items'] if i['origin'] == 'app')
    assert shown['fix']['applied_to_running_app'] is False and shown['fix']['scope'] == 'isolated_copy'
    assert shown['fix']['target_version'] == '4.18.1' and shown['fix']['diff'] == '--- a\n+++ b\n'
    assert shown['status_text'] == STATUS_TEXT['FIX_VERIFIED']
    section = report['fix_run']
    assert section['status'] == 'COMPLETED' and section['commit_sha'] == COMMIT and section['image_digest'] == DIGEST
    assert section['applied_to_running_app'] is False and section['combined']['outcome'] == 'FIX_VERIFIED'
    actions = [a['action'] for a in report['proposed_actions'] if a['action'] == 'create_pull_request']
    assert len(actions) == 7


def test_pull_request_is_attached_and_merge_is_not_assumed(db, check):
    run = run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item()]))
    fix_runs.record_pull_request(db, run.id, url='https://github.com/tomirizz/bultshield-training-app/pull/1',
                                 branch='bultshield/fix-6851c7e8a7', base_sha=COMMIT, created=True)
    report = report_of(db, check)
    assert report['fix_run']['pull_request']['merged'] is False
    assert set(states(report).values()) == {'FIX_VERIFIED'} and 'FIX_DEPLOYED' not in report['facts']['by_status']
    actions = {a['action'] for a in report['proposed_actions']}
    assert 'review_pull_request' in actions and 'create_pull_request' not in actions
    detail = next(a['detail'] for a in report['proposed_actions'] if a['action'] == 'review_pull_request')
    assert 'не исправлено' in detail


@pytest.mark.parametrize('url', ['http://github.com/a/b/pull/1', 'https://evil.example/a/b/pull/1', 'https://github.com/a/b/pull/x',
                                 'https://github.com/a/b/pull/1/files', 'javascript:alert(1)', None, 5])
def test_pull_request_url_is_validated(db, check, url):
    run = run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item()]))
    with pytest.raises(FixRunError):
        fix_runs.record_pull_request(db, run.id, url=url, branch='b', base_sha=COMMIT, created=True)
    assert db.get(DependencyFixRun, run.id).pull_request is None


@pytest.mark.parametrize('chosen,expected', [
    (item(needs_review=True, reason='Обновление меняет мажорную версию: перед применением нужен просмотр человеком.'), 'MANUAL_REVIEW'),
    (item(status=FIX_PROPOSED, reason='Исправление предложено, но проверка не завершена: нет сети.'), 'FIX_PROPOSED'),
    (item(status=MANUAL, reason='обновление ломает приложение: тесты не прошли'), 'MANUAL_REVIEW'),
    (item(status='something_new'), 'MANUAL_REVIEW'),
])
def test_statuses_follow_the_agent_and_unknown_is_manual(db, check, chosen, expected):
    run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([chosen], combined=None))
    report = report_of(db, check)
    assert set(states(report).values()) == {expected}
    shown = next(i for i in report['findings']['items'] if i['origin'] == 'app')
    assert shown['status_reason']
    assert (shown['manual_reason'] is not None) == (expected == 'MANUAL_REVIEW')


def test_manual_item_keeps_its_reason_and_action(db, check):
    chosen = item(status=MANUAL, reason='обновление ломает приложение: тесты не прошли')
    run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([chosen], combined=None))
    report = report_of(db, check)
    shown = next(i for i in report['findings']['items'] if i['origin'] == 'app')
    assert shown['manual_reason'] == 'обновление ломает приложение: тесты не прошли'
    assert {a['action'] for a in report['proposed_actions']} == {'manual_review'}


def test_set_that_fails_together_is_not_reported_as_verified(db, check):
    combined = {'packages': ['lodash'], 'outcome': 'BREAKS_APP', 'reason': 'тесты не прошли', 'scan_db_updated_at': None}
    run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item()], combined=combined))
    report = report_of(db, check)
    assert set(states(report).values()) == {'FIX_PROPOSED'}
    shown = next(i for i in report['findings']['items'] if i['origin'] == 'app')
    assert 'вместе' in shown['status_reason'] and 'тесты не прошли' in shown['status_reason']
    assert 'rerun_verification' in {a['action'] for a in report['proposed_actions']}


def test_missing_combined_result_is_not_verified(db, check):
    run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item()], combined=None))
    assert set(states(report_of(db, check)).values()) == {'FIX_PROPOSED'}


def test_agent_failure_is_failed_and_findings_stay_found(db, check):
    def boom(project_dir, findings, **kwargs):
        raise RuntimeError('/Users/secret/path token=abc123')
    with pytest.raises(FixRunError) as raised:
        run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=boom)
    assert 'abc123' not in str(raised.value) and '/Users' not in str(raised.value)
    run = db.scalar(select(DependencyFixRun))
    assert run.status == 'FAILED' and 'abc123' not in run.error_message and '/Users' not in run.error_message
    report = report_of(db, check)
    assert set(states(report).values()) == {'FOUND'}
    assert report['fix_run']['status'] == 'FAILED' and report['fix_run']['error_message']


def test_running_run_shows_verifying_and_blocks_a_second_run(db, check):
    create_run(db, check, COMMIT)
    report = report_of(db, check)
    assert set(states(report).values()) == {'VERIFYING'} and report['fix_run']['status'] == 'RUNNING'
    assert report['facts']['by_status'] == {'VERIFYING': 7, 'MANUAL_REVIEW': 7}
    with pytest.raises(FixRunError, match='уже проверяются'):
        create_run(db, check, COMMIT)


def test_stale_run_is_treated_as_failed(db, check):
    run = create_run(db, check, COMMIT)
    run.started_at = fix_runs.now() - fix_runs.STALE_AFTER - timedelta(minutes=1)
    db.commit()
    assert effective_status(run) == 'FAILED'
    report = report_of(db, check)
    assert set(states(report).values()) == {'FOUND'} and report['fix_run']['status'] == 'FAILED'
    again = create_run(db, check, COMMIT)   # зависший запуск не блокирует новый
    assert again.id != run.id and db.get(DependencyFixRun, run.id).status == 'FAILED'


def test_failed_rerun_does_not_erase_an_earlier_result(db, check):
    run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item()]))

    def boom(project_dir, findings, **kwargs):
        raise RuntimeError('x')
    with pytest.raises(FixRunError):
        run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=boom)
    report = report_of(db, check)
    assert set(states(report).values()) == {'FIX_VERIFIED'} and report['fix_run']['status'] == 'FAILED'


def test_result_for_another_image_digest_is_ignored(db, check):
    run = run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item()]))
    run.image_digest = 'sha256:' + 'b' * 64
    db.commit()
    assert set(states(report_of(db, check)).values()) == {'FOUND'}


def test_agent_is_never_started_for_a_failed_or_foreign_scan(client, db, worker_db, monkeypatch):
    scan = create_image_scan(db, repository(client), REFERENCE)

    def fail(reference):
        raise ImageScanError('Trivy завершился с ошибкой (1); проверка неполная.')
    monkeypatch.setattr(image_pipeline, 'run_image_scan', fail)
    worker.process_job(worker.claim_job())
    agent = agent_returning([item()])
    with pytest.raises(FixRunError, match='не завершилась успешно'):
        run_agent_for_scan(db, scan.id, '/x', commit_sha=COMMIT, agent=agent)
    with pytest.raises(FixRunError, match='не найдена'):
        run_agent_for_scan(db, uuid.uuid4(), '/x', commit_sha=COMMIT, agent=agent)
    assert agent.calls == [] and db.scalars(select(DependencyFixRun)).all() == []


def test_agent_is_not_started_for_a_source_scan(client, db, worker_db):
    project = client.post('/api/projects', json={'name': 'p', 'repository': {'url': 'https://github.com/example/demo', 'default_branch': 'main'}}).json()
    scan = client.post('/api/scans', json={'repository_id': project['repositories'][0]['id']}).json()
    with pytest.raises(FixRunError, match='только с проверками образа'):
        create_run(db, uuid.UUID(scan['id']), COMMIT)


@pytest.mark.parametrize('sha', ['abc', 'A' * 40, COMMIT + '0', 'main', '--version', COMMIT[:-1] + 'g'])
def test_commit_must_be_a_full_lowercase_sha(db, check, sha):
    with pytest.raises(FixRunError, match='SHA'):
        create_run(db, check, sha)
    assert db.scalars(select(DependencyFixRun)).all() == []


def test_a_finished_run_cannot_be_completed_twice(db, check):
    run = run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item()]))
    result = AgentResult([item()], [], {}, combined=None)
    with pytest.raises(FixRunError):
        complete_run(db, run.id, result, [])
    assert db.get(DependencyFixRun, run.id).combined['outcome'] == 'FIX_VERIFIED'


def test_large_diffs_and_logs_are_capped(db, check):
    big = item()
    big.verification['diff'] = 'x' * (fix_runs.MAX_DIFF + 500)
    big.verification['steps'][0]['log_tail'] = 'y' * (fix_runs.MAX_LOG + 500)
    run = run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([big]))
    saved = db.get(DependencyFixRun, run.id).items[0]['verification']
    assert len(saved['diff']) < fix_runs.MAX_DIFF + 50 and saved['diff'].endswith('[обрезано]')
    assert len(saved['steps'][0]['log_tail']) < fix_runs.MAX_LOG + 50


def git(path, *args):
    subprocess.run(['git', '-C', str(path), '-c', 'user.email=a@b.c', '-c', 'user.name=t', *args], check=True, capture_output=True)


def test_commit_is_taken_from_a_clean_git_project(tmp_path):
    assert fix_runs.detect_commit(tmp_path) is None   # не git: версия кода не определена
    git(tmp_path, 'init', '-q', '-b', 'main')
    (tmp_path / 'package.json').write_text('{}')
    git(tmp_path, 'add', '-A')
    git(tmp_path, 'commit', '-q', '-m', 'one')
    sha = fix_runs.detect_commit(tmp_path)
    assert fix_runs.COMMIT.fullmatch(sha)
    (tmp_path / 'package.json').write_text('{"changed": 1}')
    with pytest.raises(FixRunError, match='незакоммиченные'):
        fix_runs.detect_commit(tmp_path)


def test_run_agent_uses_the_detected_commit(db, check, tmp_path):
    git(tmp_path, 'init', '-q', '-b', 'main')
    (tmp_path / 'package.json').write_text('{}')
    git(tmp_path, 'add', '-A')
    git(tmp_path, 'commit', '-q', '-m', 'one')
    run = run_agent_for_scan(db, check, tmp_path, agent=agent_returning([item()]))
    assert run.commit_sha == fix_runs.detect_commit(tmp_path)


def test_runs_are_isolated_between_owners(engine, db, check):
    run = run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item()]))
    project = db.get(Project, run.project_id)
    stranger = uuid.uuid4()
    with Session(engine) as scoped:
        isolate(scoped, project.owner_id)
        assert scoped.get(DependencyFixRun, run.id) is not None
    with Session(engine) as scoped:
        isolate(scoped, stranger)
        assert scoped.get(DependencyFixRun, run.id) is None
        assert scoped.scalars(select(DependencyFixRun)).all() == []
        assert scoped.get(Scan, check) is None and scoped.scalars(select(Repository)).all() == []


def test_failed_scan_status_is_part_of_the_guard(db, check):
    scan = db.get(Scan, check)
    scan.status = ScanStatus.FAILED
    db.commit()
    with pytest.raises(FixRunError):
        create_run(db, check, COMMIT)

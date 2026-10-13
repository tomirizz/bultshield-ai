import json
import uuid

import pytest
from app import fix_runs, image_pipeline, worker
from app.check_report import load_report
from app.fix_deployment import confirm_deployment
from app.fix_runs import FixRunError, record_pull_request, run_agent_for_scan
from app.github_pr import GitHubError, fetch_pull_request
from app.image_report import ImageReport, parse_image_report
from app.image_scan import ImageScanError, ImageScanResult
from app.models import DependencyFixRun, Scan
from test_fix_runs import COMMIT, agent_returning, check, item  # noqa: F401
from test_gitleaks import worker_db as worker_db  # noqa: F401
from test_image_jobs import DIGEST, FIXTURE, REFERENCE, create_image_scan, repository, scan_result  # noqa: F401

REPO = 'tomirizz/bultshield-training-app'
BRANCH = 'bultshield/fix-6851c7e8a7'
PR_URL = f'https://github.com/{REPO}/pull/1'
NEW_DIGEST = 'sha256:' + 'c' * 64
MERGED_AT = '2026-10-08T08:00:00Z'
MERGE_SHA = 'b' * 40
LODASH = {'name': 'lodash', 'version': '4.18.1', 'path': 'app/node_modules/lodash/package.json', 'origin': 'app'}


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    monkeypatch.setenv('IMAGE_ALLOWED_REGISTRIES', 'localhost:5001')
    monkeypatch.setenv('FIX_PR_ALLOWED_REPOS', REPO)


def pull_request(**changes):
    data = {'number': 1, 'state': 'closed', 'merged': True, 'merged_at': MERGED_AT, 'merge_commit_sha': MERGE_SHA,
            'head': {'ref': BRANCH}, 'base': {'ref': 'main'}, 'html_url': PR_URL}
    data.update(changes)
    return data


class FakeGitHub:
    def __init__(self, data=None, error=None):
        self.data, self.error, self.calls = data if data is not None else pull_request(), error, []

    def request(self, method, path, body=None, *, raw=False):
        self.calls.append((method, path))
        if self.error:
            raise self.error
        return self.data


def rescan_result(*, digest=NEW_DIGEST, created='2026-10-08T10:00:00Z', packages=(LODASH,), keep=(), revision=None):
    """Результат повторного скана пересобранного образа: находки lodash исчезли (кроме keep), пакет виден."""
    parsed = parse_image_report(json.loads(FIXTURE.read_text()))
    findings = [f for f in parsed.findings if f['origin'] != 'app' or f['rule_id'] in keep]
    summary = {**parsed.summary, 'image_created': created, 'image_revision': revision, 'packages': [dict(p) for p in packages]}
    return ImageScanResult(REFERENCE, digest, 'linux/amd64', '2026-10-08T07:38:55Z', ImageReport(findings, summary))


def rescan(client, db, monkeypatch, result, reference=REFERENCE):
    scan = create_image_scan(db, repository_of(db), reference)
    monkeypatch.setattr(image_pipeline, 'run_image_scan', lambda ref: result)
    worker.process_job(worker.claim_job())
    return scan.id


def repository_of(db):
    from app.models import Repository
    from sqlalchemy import select
    return db.scalars(select(Repository)).one().id


@pytest.fixture
def run(db, check):  # noqa: F811
    created = run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item()]))
    record_pull_request(db, created.id, url=PR_URL, branch=BRANCH, base_sha=COMMIT, created=True)
    return created


def report_of(db, scan_id):
    return load_report(db, db.get(Scan, scan_id), limit=500)


def states(report):
    return {i['rule_id']: i['status'] for i in report['findings']['items'] if i['origin'] == 'app'}


def confirm(db, run, scan_id, github=None):
    return confirm_deployment(db, run.id, scan_id, github or FakeGitHub())


def test_applied_only_with_all_evidence(client, db, worker_db, monkeypatch, check, run):  # noqa: F811
    again = rescan(client, db, monkeypatch, rescan_result())
    done = confirm(db, run, again)
    proof = done.deployment
    assert proof['status'] == 'CONFIRMED' and proof['counts'] == {'gone': 7, 'still_detected': 0, 'not_seen': 0}
    assert proof['image_digest'] == NEW_DIGEST and proof['base_image_digest'] == DIGEST and proof['reasons'] == []
    assert done.pull_request['merged'] is True and done.pull_request['merge_commit_sha'] == MERGE_SHA
    report = report_of(db, check)
    assert set(states(report).values()) == {'FIX_DEPLOYED'}
    assert report['facts']['by_status'] == {'FIX_DEPLOYED': 7, 'MANUAL_REVIEW': 7}
    shown = next(i for i in report['findings']['items'] if i['origin'] == 'app')
    assert shown['fix']['applied_to_running_app'] is False and shown['fix']['scope'] == 'published_image'
    assert shown['fix']['published_image_verified'] is True
    assert NEW_DIGEST in shown['status_reason'] and '№1' in shown['status_reason'] and 'опубликованный образ' in shown['status_reason']
    assert report['deployment']['status'] == 'CONFIRMED' and report['deployment']['scope'] == 'published_image'
    assert not any(a['action'] in ('create_pull_request', 'review_pull_request') for a in report['proposed_actions'] if a['finding_id'] == shown['id'])


def test_nothing_is_applied_before_the_check(db, check, run):  # noqa: F811
    report = report_of(db, check)
    assert set(states(report).values()) == {'FIX_VERIFIED'} and report['deployment'] is None
    assert 'FIX_DEPLOYED' not in report['facts']['by_status']


@pytest.mark.parametrize('data,needle', [
    (pull_request(merged=False, merged_at=None, merge_commit_sha=None, state='open'), 'не слит'),
    (pull_request(head={'ref': 'someone/else'}), 'не совпадает'),
])
def test_unmerged_or_foreign_pr_is_not_confirmed(client, db, worker_db, monkeypatch, check, run, data, needle):  # noqa: F811
    again = rescan(client, db, monkeypatch, rescan_result())
    proof = confirm(db, run, again, FakeGitHub(data)).deployment
    assert proof['status'] == 'NOT_CONFIRMED' and any(needle in r for r in proof['reasons']) and proof['findings'] == {}
    report = report_of(db, check)
    assert set(states(report).values()) == {'FIX_VERIFIED'} and 'FIX_DEPLOYED' not in report['facts']['by_status']
    assert report['deployment']['reasons']


@pytest.mark.parametrize('result,needle', [
    (rescan_result(digest=DIGEST), 'не менялся'),
    (rescan_result(created='2026-10-08T07:59:59Z'), 'раньше слияния'),
    (rescan_result(created=None), 'нет времени сборки'),
    (rescan_result(created='вчера'), 'нет времени сборки'),
])
def test_image_must_be_new_and_built_after_the_merge(client, db, worker_db, monkeypatch, check, run, result, needle):  # noqa: F811
    again = rescan(client, db, monkeypatch, result)
    proof = confirm(db, run, again).deployment
    assert proof['status'] == 'NOT_CONFIRMED' and any(needle in r for r in proof['reasons'])
    assert set(states(report_of(db, check)).values()) == {'FIX_VERIFIED'}


def test_a_finding_that_remains_is_manual_not_applied(client, db, worker_db, monkeypatch, check, run):  # noqa: F811
    again = rescan(client, db, monkeypatch, rescan_result(keep=('CVE-2020-8203',)))
    proof = confirm(db, run, again).deployment
    assert proof['status'] == 'CONFIRMED' and proof['counts'] == {'gone': 6, 'still_detected': 1, 'not_seen': 0}
    assert any('осталось' in r for r in proof['reasons'])
    seen = states(report_of(db, check))
    assert seen.pop('CVE-2020-8203') == 'MANUAL_REVIEW' and set(seen.values()) == {'FIX_DEPLOYED'}


def test_a_package_that_is_not_visible_cannot_prove_a_fix(client, db, worker_db, monkeypatch, check, run):  # noqa: F811
    again = rescan(client, db, monkeypatch, rescan_result(packages=()))
    proof = confirm(db, run, again).deployment
    assert proof['status'] == 'NOT_CONFIRMED' and proof['counts']['not_seen'] == 7
    report = report_of(db, check)
    assert set(states(report).values()) == {'FIX_VERIFIED'}
    shown = next(i for i in report['findings']['items'] if i['origin'] == 'app')
    assert 'не виден' in shown['status_reason'] and shown['fix']['applied_to_running_app'] is False


def test_truncated_package_list_cannot_prove_a_fix(client, db, worker_db, monkeypatch, check, run):  # noqa: F811
    monkeypatch.setattr(image_pipeline, 'MAX_APP_PACKAGES', 1)   # lodash попал в список, но список обрезан
    other = {'name': 'express', 'version': '4.21.0', 'path': 'app/node_modules/express/package.json', 'origin': 'app'}
    again = rescan(client, db, monkeypatch, rescan_result(packages=(LODASH, other)))
    assert db.get(Scan, again).scanner_results['trivy']['app_packages_truncated'] is True
    assert confirm(db, run, again).deployment['counts']['not_seen'] == 7
    assert set(states(report_of(db, check)).values()) == {'FIX_VERIFIED'}


def test_scan_without_package_list_cannot_prove_a_fix(client, db, worker_db, monkeypatch, check, run):  # noqa: F811
    again = rescan(client, db, monkeypatch, rescan_result())
    stored = db.get(Scan, again)
    stored.scanner_results = {'trivy': {k: v for k, v in stored.scanner_results['trivy'].items() if not k.startswith('app_packages')}}
    db.commit()
    assert confirm(db, run, again).deployment['counts']['not_seen'] == 7


def test_pipeline_keeps_only_application_packages(client, db, worker_db, monkeypatch, check):  # noqa: F811
    tooling = {'name': 'npm', 'version': '11.0.0', 'path': 'usr/local/lib/node_modules/npm/package.json', 'origin': 'base-tooling'}
    again = rescan(client, db, monkeypatch, rescan_result(packages=(LODASH, tooling)))
    stored = db.get(Scan, again).scanner_results['trivy']
    assert stored['app_packages'] == [{'name': 'lodash', 'version': '4.18.1', 'path': LODASH['path']}]
    assert stored['app_packages_truncated'] is False and 'packages' not in stored
    assert stored['image_created'] == '2026-10-08T10:00:00Z'


def test_unusable_rescans_are_rejected_and_change_nothing(client, db, worker_db, monkeypatch, check, run):  # noqa: F811
    with pytest.raises(FixRunError, match='не найдена'):
        confirm(db, run, uuid.uuid4())
    with pytest.raises(FixRunError, match='новая проверка'):
        confirm(db, run, check)
    other = rescan(client, db, monkeypatch, rescan_result(), reference='localhost:5001/other-app:main')
    with pytest.raises(FixRunError, match='другой образ'):
        confirm(db, run, other)

    def fail(reference):
        raise ImageScanError('Trivy завершился с ошибкой (1); проверка неполная.')
    scan = create_image_scan(db, repository_of(db), REFERENCE)
    monkeypatch.setattr(image_pipeline, 'run_image_scan', fail)
    worker.process_job(worker.claim_job())
    with pytest.raises(FixRunError, match='не завершилась успешно'):
        confirm(db, run, scan.id)
    assert db.get(DependencyFixRun, run.id).deployment is None
    assert set(states(report_of(db, check)).values()) == {'FIX_VERIFIED'}


def test_a_source_scan_cannot_confirm(client, db, worker_db, check, run):  # noqa: F811
    project = client.post('/api/projects', json={'name': 'p2', 'repository': {'url': 'https://github.com/example/other', 'default_branch': 'main'}}).json()
    source = client.post('/api/scans', json={'repository_id': project['repositories'][0]['id']}).json()
    with pytest.raises(FixRunError, match='только по проверке образа'):
        confirm(db, run, uuid.UUID(source['id']))


def test_github_failure_is_not_a_confirmation_and_leaks_nothing(client, db, worker_db, monkeypatch, check, run):  # noqa: F811
    again = rescan(client, db, monkeypatch, rescan_result())
    with pytest.raises(FixRunError, match='Не удалось проверить PR') as raised:
        confirm(db, run, again, FakeGitHub(error=GitHubError('GitHub недоступен: URLError.')))
    assert 'ghp_' not in str(raised.value)
    assert db.get(DependencyFixRun, run.id).deployment is None
    assert set(states(report_of(db, check)).values()) == {'FIX_VERIFIED'}


def test_a_run_without_pull_request_cannot_be_confirmed(client, db, worker_db, monkeypatch, check):  # noqa: F811
    created = run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item()]))
    again = rescan(client, db, monkeypatch, rescan_result())
    with pytest.raises(FixRunError, match='не привязан PR'):
        confirm(db, created, again)


def test_a_bad_second_attempt_does_not_erase_the_proof(client, db, worker_db, monkeypatch, check, run):  # noqa: F811
    again = rescan(client, db, monkeypatch, rescan_result())
    confirm(db, run, again)
    stale = rescan(client, db, monkeypatch, rescan_result(created='2026-10-08T07:00:00Z', digest='sha256:' + 'd' * 64))
    proof = confirm(db, run, stale).deployment
    assert proof['status'] == 'CONFIRMED' and proof['last_attempt']['status'] == 'NOT_CONFIRMED' and proof['image_digest'] == NEW_DIGEST
    assert set(states(report_of(db, check)).values()) == {'FIX_DEPLOYED'}


def test_proof_survives_a_newer_run(client, db, worker_db, monkeypatch, check, run):  # noqa: F811
    again = rescan(client, db, monkeypatch, rescan_result())
    confirm(db, run, again)
    run_agent_for_scan(db, check, '/x', commit_sha=COMMIT, agent=agent_returning([item(status='manual_intervention', reason='нет версий')], combined=None))
    assert set(states(report_of(db, check)).values()) == {'FIX_DEPLOYED'}


def test_proof_for_another_image_digest_is_ignored(client, db, worker_db, monkeypatch, check, run):  # noqa: F811
    again = rescan(client, db, monkeypatch, rescan_result())
    stored = confirm(db, run, again)
    stored.image_digest = 'sha256:' + 'e' * 64
    db.commit()
    assert set(states(report_of(db, check)).values()) == {'FOUND'}


def test_new_pull_request_resets_old_proof(client, db, worker_db, monkeypatch, check, run):  # noqa: F811
    again = rescan(client, db, monkeypatch, rescan_result())
    confirm(db, run, again)
    record_pull_request(db, run.id, url=f'https://github.com/{REPO}/pull/2', branch=BRANCH, base_sha=COMMIT, created=True)
    stored = db.get(DependencyFixRun, run.id)
    assert stored.deployment is None and stored.pull_request['number'] == 2 and stored.pull_request['merged'] is False
    assert set(states(report_of(db, check)).values()) == {'FIX_VERIFIED'}


def test_pull_request_record_has_repo_and_number(db, run):
    saved = db.get(DependencyFixRun, run.id).pull_request
    assert saved['repo'] == REPO and saved['number'] == 1 and saved['merged'] is False and saved['branch'] == BRANCH


# --- чтение PR с GitHub ---

def test_fetch_pull_request_reads_state_only():
    github = FakeGitHub()
    info = fetch_pull_request(github, REPO, 1)
    assert info['merged'] is True and info['merge_commit_sha'] == MERGE_SHA and info['head_ref'] == BRANCH
    assert github.calls == [('GET', f'/repos/{REPO}/pulls/1')]


def test_fetch_pull_request_unmerged_has_no_merge_data():
    info = fetch_pull_request(FakeGitHub(pull_request(merged=False, merged_at='2026-10-08T08:00:00Z', merge_commit_sha=MERGE_SHA)), REPO, 1)
    assert info['merged'] is False and info['merged_at'] is None and info['merge_commit_sha'] is None


@pytest.mark.parametrize('repo,number,data', [
    ('someone/else', 1, None),                       # репозиторий не в списке разрешённых
    ('bad repo', 1, None),
    (REPO, 0, None), (REPO, True, None), (REPO, '1', None),
    (REPO, 1, pull_request(number=2)),                # GitHub вернул другой PR
    (REPO, 1, pull_request(merge_commit_sha=None)),   # «слит», но без коммита
    (REPO, 1, pull_request(merge_commit_sha='x' * 40)),
    (REPO, 1, pull_request(merged_at=None)),
    (REPO, 1, pull_request(html_url='https://evil.example/x')),
    (REPO, 1, ['not', 'a', 'pull request']),
])
def test_fetch_pull_request_rejects_bad_input_and_odd_answers(repo, number, data):
    with pytest.raises(GitHubError):
        fetch_pull_request(FakeGitHub(data), repo, number)


def test_fetch_uses_nothing_but_get():
    github = FakeGitHub()
    fetch_pull_request(github, REPO, 1)
    assert {method for method, _ in github.calls} == {'GET'}
    assert fix_runs  # модуль подключён: запись PR не вызывает GitHub

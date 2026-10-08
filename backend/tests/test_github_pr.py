import io
import json
import re
import urllib.error
from types import SimpleNamespace
from urllib.parse import unquote

import pytest
from app import github_pr
from app.fix_agent import FIX_PASSED
from app.github_pr import (
    API,
    BaseMovedError,
    FixSet,
    GitHubClient,
    GitHubError,
    build_pr_body,
    create_fix_pr,
    fix_set_from_agent,
)

REPO = 'tomirizz/bultshield-training'
SHA = 'a' * 40
TOKEN = 'github_pat_' + 'X' * 40
ORIGINAL = {'package.json': '{"name": "demo"}\n', 'package-lock.json': '{"lockfileVersion": 3}\n'}
FIXED = {'package.json': '{"name": "demo", "overrides": {"qs": "6.16.0"}}\n',
         'package-lock.json': '{"lockfileVersion": 3, "x": 1}\n'}


def fix_set(**changes):
    values = dict(
        packages=[{'package': 'qs', 'from': '6.5.5', 'to': '6.16.0', 'method': 'override', 'resolves': ['CVE-2022-24999']},
                  {'package': 'form-data', 'from': '2.3.3', 'to': '2.5.6', 'method': 'override', 'resolves': ['CVE-2025-7783']}],
        files=dict(FIXED), original=dict(ORIGINAL), manual=[{'package': 'request', 'reason': 'исправленной версии нет'}],
        db_updated_at='2026-10-08T07:38:55Z')
    values.update(changes)
    return FixSet(**values)


class Response:
    def __init__(self, body):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit=-1):
        return self.body if limit < 0 else self.body[:limit]


class FakeGitHub:
    """Подставляется вместо сети: хранит «репозиторий» в памяти и записывает все запросы."""

    def __init__(self, files=None, head=SHA):
        self.files = dict(ORIGINAL if files is None else files)
        self.refs = {'main': head}
        self.commits = {head: {'tree': {'sha': 'tree-0'}}}
        self.pulls, self.log, self.fail = [], [], {}
        self.counter = 0

    def next(self, prefix):
        self.counter += 1
        return f'{prefix}-{self.counter}'

    def error(self, url, code, message):
        return urllib.error.HTTPError(url, code, message, {}, io.BytesIO(json.dumps({'message': message}).encode()))

    def __call__(self, request, timeout):
        method, path = request.get_method(), request.full_url[len(API):]
        body = json.loads(request.data) if request.data else None
        self.log.append({'method': method, 'path': path, 'body': body, 'headers': dict(request.header_items())})
        route = f'{method} {re.sub(r"^/repos/[^/]+/[^/]+", "", path)}'
        for needle, (code, message) in self.fail.items():
            if route.startswith(needle):
                raise self.error(request.full_url, code, message)
        if route.startswith('GET /pulls'):
            return Response([p for p in self.pulls if p['head'] in unquote(path)])
        if route.startswith('GET /git/ref/heads/'):
            name = route.split('/git/ref/heads/')[1]
            if name not in self.refs:
                raise self.error(request.full_url, 404, 'Not Found')
            return Response({'object': {'sha': self.refs[name]}})
        if route.startswith('GET /contents/'):
            name = route.split('/contents/')[1].split('?')[0]
            if name not in self.files:
                raise self.error(request.full_url, 404, 'Not Found')
            return Response(self.files[name].encode())
        if route.startswith('GET /git/commits/'):
            return Response(self.commits[route.split('/git/commits/')[1]])
        if route == 'POST /git/blobs':
            return Response({'sha': self.next('blob')})
        if route == 'POST /git/trees':
            return Response({'sha': self.next('tree')})
        if route == 'POST /git/commits':
            sha = self.next('commit')
            self.commits[sha] = {'tree': {'sha': body['tree']}}
            return Response({'sha': sha})
        if route == 'POST /git/refs':
            name = body['ref'].removeprefix('refs/heads/')
            if name in self.refs:
                raise self.error(request.full_url, 422, 'Reference already exists')
            self.refs[name] = body['sha']
            return Response({'ref': body['ref']})
        if route == 'POST /pulls':
            number = len(self.pulls) + 1
            pull = {'number': number, 'html_url': f'https://github.com/{REPO}/pull/{number}', 'head': body['head']}
            self.pulls.append(pull)
            return Response(pull)
        raise AssertionError('неожиданный запрос: ' + route)

    def calls(self, method, fragment):
        return [r for r in self.log if r['method'] == method and fragment in r['path']]


@pytest.fixture
def hub():
    return FakeGitHub()


@pytest.fixture
def client(hub):
    return GitHubClient(TOKEN, opener=hub)


def make(client, **overrides):
    arguments = dict(base_branch='main', base_sha=SHA, fix=fix_set(), confirmed=True, allowed=[REPO])
    arguments.update(overrides)
    return create_fix_pr(client, REPO, **arguments)


def test_pr_is_created_with_one_commit_and_exact_files(hub, client):
    result = make(client)
    assert result['created'] and result['number'] == 1 and result['url'] == f'https://github.com/{REPO}/pull/1'
    blobs = [r['body'] for r in hub.calls('POST', '/git/blobs')]
    assert [b['content'] for b in blobs] == [FIXED['package.json'], FIXED['package-lock.json']]
    (tree,) = [r['body'] for r in hub.calls('POST', '/git/trees')]
    assert tree['base_tree'] == 'tree-0' and [e['path'] for e in tree['tree']] == ['package.json', 'package-lock.json']
    (commit,) = [r['body'] for r in hub.calls('POST', '/git/commits')]
    assert commit['parents'] == [SHA] and 'qs, form-data' in commit['message']
    (pull,) = [r['body'] for r in hub.calls('POST', '/pulls')]
    assert pull['base'] == 'main' and pull['head'] == result['branch'] and pull['head'].startswith('bultshield/fix-')
    assert pull['draft'] is False and pull['maintainer_can_modify'] is False
    assert hub.refs[result['branch']] == result['commit']


def test_pr_body_explains_limits_and_manual_items(hub, client):
    make(client)
    body = hub.calls('POST', '/pulls')[0]['body']['body']
    for text in ('`qs`', 'CVE-2022-24999', 'overrides', 'работающее приложение не исправлено', '`request`',
                 'исправленной версии нет', 'Слияние выполняет человек', 'база CVE от 2026-10-08'):
        assert text in body


def test_main_branch_is_never_touched_and_nothing_is_merged(hub, client):
    make(client)
    assert hub.refs['main'] == SHA
    assert not [r for r in hub.log if r['method'] in ('PUT', 'PATCH', 'DELETE')]
    assert not [r for r in hub.log if 'merge' in r['path']]


def test_repeat_call_returns_the_open_pr_without_new_commits(hub, client):
    first = make(client)
    log_size = len(hub.log)
    second = make(client)
    assert second == {'created': False, 'number': 1, 'url': first['url'], 'branch': first['branch']}
    assert [r['method'] for r in hub.log[log_size:]] == ['GET'] and len(hub.pulls) == 1


def test_branch_name_depends_on_content_and_base(hub, client):
    one = make(client)['branch']
    other = FakeGitHub()
    changed = fix_set(files={**FIXED, 'package.json': '{"name": "demo", "x": 2}\n'})
    two = make(GitHubClient(TOKEN, opener=other), fix=changed)['branch']
    assert one != two


def test_stale_base_commit_is_refused_before_anything_is_written():
    hub = FakeGitHub(head='b' * 40)
    with pytest.raises(BaseMovedError, match='другому коммиту'):
        make(GitHubClient(TOKEN, opener=hub))
    assert not [r for r in hub.log if r['method'] == 'POST']


def test_repository_files_that_differ_from_verified_ones_are_refused():
    hub = FakeGitHub(files={**ORIGINAL, 'package.json': '{"name": "someone else edited this"}\n'})
    with pytest.raises(BaseMovedError, match='package.json'):
        make(GitHubClient(TOKEN, opener=hub))
    assert not [r for r in hub.log if r['method'] == 'POST']


def test_leftover_branch_with_the_same_tree_is_reused(hub, client):
    # Прерванный запуск: ветка создана, PR нет. Два blob'а дают счётчик 2, значит, новое дерево получит имя tree-3.
    branch = github_pr._branch_name(SHA, FIXED)
    hub.refs[branch] = 'old'
    hub.commits['old'] = {'tree': {'sha': 'tree-3'}}
    result = make(client)
    assert result['created'] and result['number'] == 1 and hub.refs[branch] == 'old'


def test_leftover_branch_with_different_content_is_an_error(hub, client):
    branch = github_pr._branch_name(SHA, FIXED)
    hub.refs[branch] = 'old'
    hub.commits['old'] = {'tree': {'sha': 'something-else'}}
    with pytest.raises(GitHubError, match='уже существует с другим содержимым'):
        make(client)
    assert not hub.calls('POST', '/pulls')


@pytest.mark.parametrize('confirmed', [False, None, 'yes', 1])
def test_confirmation_must_be_exactly_true(hub, client, confirmed):
    with pytest.raises(GitHubError, match='подтверждения'):
        make(client, confirmed=confirmed)
    assert hub.log == []


def test_repository_must_be_on_the_allowlist(hub, client):
    with pytest.raises(GitHubError, match='FIX_PR_ALLOWED_REPOS'):
        make(client, allowed=['someone/else'])
    with pytest.raises(GitHubError, match='FIX_PR_ALLOWED_REPOS'):
        make(client, allowed=[])
    assert hub.log == []


def test_allowlist_defaults_to_environment_and_is_empty(hub, client, monkeypatch):
    monkeypatch.delenv('FIX_PR_ALLOWED_REPOS', raising=False)
    with pytest.raises(GitHubError, match='FIX_PR_ALLOWED_REPOS'):
        create_fix_pr(client, REPO, base_branch='main', base_sha=SHA, fix=fix_set(), confirmed=True)
    monkeypatch.setenv('FIX_PR_ALLOWED_REPOS', 'TomiRizz/Bultshield-Training')
    assert create_fix_pr(client, REPO, base_branch='main', base_sha=SHA, fix=fix_set(), confirmed=True)['created']


@pytest.mark.parametrize('repo', ['', 'noslash', 'a/b/c', '../x/y', 'owner/na me', 'owner/', '/name', 'o;w/n'])
def test_unsafe_repository_names_are_rejected(hub, client, repo):
    with pytest.raises(GitHubError):
        create_fix_pr(client, repo, base_branch='main', base_sha=SHA, fix=fix_set(), confirmed=True, allowed=[repo])
    assert hub.log == []


@pytest.mark.parametrize('field,value', [
    ('base_branch', '../main'), ('base_branch', 'a b'), ('base_branch', '-x'), ('base_branch', 'x.lock'), ('base_branch', 'x/'),
    ('base_sha', 'main'), ('base_sha', 'A' * 40), ('base_sha', 'a' * 39), ('project_path', '../x/'), ('project_path', '/abs/'),
    ('project_path', 'a b/')])
def test_unsafe_references_are_rejected(hub, client, field, value):
    with pytest.raises(GitHubError):
        make(client, **{field: value})
    assert hub.log == []


@pytest.mark.parametrize('files', [
    {**FIXED, '.github/workflows/ci.yml': 'x'}, {'package.json': FIXED['package.json']},
    {**FIXED, 'package.json': ''}, {**FIXED, 'package-lock.json': 'x' * (5 * 1024 * 1024 + 1)}, dict(ORIGINAL)])
def test_only_the_two_manifest_files_with_real_changes_are_allowed(hub, client, files):
    with pytest.raises(GitHubError):
        make(client, fix=fix_set(files=files))
    assert hub.log == []


def test_project_subdirectory_is_used_in_paths():
    hub = FakeGitHub(files={'app/package.json': ORIGINAL['package.json'], 'app/package-lock.json': ORIGINAL['package-lock.json']})
    make(GitHubClient(TOKEN, opener=hub), project_path='app/')
    (tree,) = [r['body'] for r in hub.calls('POST', '/git/trees')]
    assert [e['path'] for e in tree['tree']] == ['app/package.json', 'app/package-lock.json']


def test_token_is_sent_only_as_bearer_header_and_never_leaks(hub, client):
    make(client)
    assert all(r['headers']['Authorization'] == f'Bearer {TOKEN}' for r in hub.log)
    assert TOKEN not in json.dumps([r['body'] for r in hub.log], default=str)


@pytest.mark.parametrize('status,needle', [(401, 'токена'), (403, 'токена'), (404, 'токена'), (500, '500')])
def test_github_errors_are_reported_without_the_token(hub, client, status, needle):
    hub.fail['POST /git/blobs'] = (status, f'Bad credentials {TOKEN}')
    with pytest.raises(GitHubError) as caught:
        make(client)
    assert needle in str(caught.value) and TOKEN not in str(caught.value) and caught.value.status == status


def test_network_failure_is_a_safe_error(hub):
    def broken(request, timeout):
        raise urllib.error.URLError(f'unreachable {TOKEN}')
    with pytest.raises(GitHubError, match='недоступен') as caught:
        make(GitHubClient(TOKEN, opener=broken))
    assert TOKEN not in str(caught.value)


def test_pr_with_unexpected_url_is_not_trusted(hub, client):
    original = hub.__call__

    def evil(request, timeout):
        response = original(request, timeout)
        if request.get_method() == 'POST' and request.full_url.endswith('/pulls'):
            return Response({'number': 1, 'html_url': 'https://evil.example/x'})
        return response
    with pytest.raises(GitHubError, match='адрес'):
        make(GitHubClient(TOKEN, opener=evil))


def test_redirects_are_not_followed():
    handler = github_pr._NoRedirect()
    assert handler.redirect_request(None, None, 302, 'Found', {}, 'https://evil.example/') is None


@pytest.mark.parametrize('token', ['', None, 'short', 'x' * 30 + '\nInjected: header', 'a b ' * 10, 'x' * 300])
def test_malformed_tokens_are_rejected(token):
    with pytest.raises(GitHubError):
        GitHubClient(token)


def test_client_from_environment(monkeypatch):
    monkeypatch.delenv('GITHUB_FIX_TOKEN', raising=False)
    with pytest.raises(GitHubError, match='GITHUB_FIX_TOKEN'):
        GitHubClient.from_environment()
    monkeypatch.setenv('GITHUB_FIX_TOKEN', TOKEN)
    assert GitHubClient.from_environment()


def test_pr_body_neutralizes_markup_in_data():
    body = build_pr_body(fix_set(
        packages=[{'package': 'x|`y`<script>', 'from': '1.0.0', 'to': '1.0.1', 'method': 'direct', 'resolves': ['CVE-1']}],
        manual=[{'package': 'bad\n# heading', 'reason': '[link](http://evil) <img src=x>'}]))
    assert '<' not in body and '`y`' not in body and '|y' not in body.split('\n')[4]
    assert 'прямая зависимость' in body and 'http' not in body.replace('---', '')


def agent_result(outcome='FIX_VERIFIED', files=True):
    item = SimpleNamespace(package='qs', installed='6.5.5', target='6.16.0', reason='r', status=FIX_PASSED,
                           plan={'resolves': ['CVE-1', 'CVE-2']})
    other = SimpleNamespace(package='request', installed='2.88.2', target=None, reason='исправления нет',
                            status='manual_intervention', plan={})
    raw = SimpleNamespace(files=dict(FIXED) if files else {}, original=dict(ORIGINAL))
    candidates = [{'package': 'qs', 'target': '6.16.0', 'method': 'override'}]
    combined = {'outcome': outcome, 'packages': ['qs'], 'candidates': candidates,
                'scan_db_updated_at': '2026-10-08T07:38:55Z'}
    return SimpleNamespace(packages=[item, other], combined=combined, combined_result=raw)


def test_fix_set_is_built_from_a_verified_agent_result():
    fix = fix_set_from_agent(agent_result())
    assert fix.packages == [{'package': 'qs', 'from': '6.5.5', 'to': '6.16.0', 'method': 'override',
                             'resolves': ['CVE-1', 'CVE-2']}]
    assert fix.files == FIXED and fix.original == ORIGINAL
    assert fix.manual == [{'package': 'request', 'reason': 'исправления нет', 'detail': ''}]


@pytest.mark.parametrize('result', [agent_result('BREAKS_APP'), agent_result(files=False),
                                    SimpleNamespace(packages=[], combined=None, combined_result=None)])
def test_unverified_results_cannot_become_a_pr(result):
    with pytest.raises(GitHubError, match='совместную проверку'):
        fix_set_from_agent(result)


def test_manual_entries_explain_why_each_package_is_left_out():
    broken = SimpleNamespace(
        package='uuid', installed='3.4.0', target='11.1.1', status='manual_intervention', plan={},
        reason='обновление ломает приложение: шаг тесты упал',
        verification={'failed_step': 'tests', 'steps': [
            {'name': 'install', 'log_tail': 'Error: не тот шаг'},
            {'name': 'tests', 'log_tail': 'ok\nError [ERR_PACKAGE_PATH_NOT_EXPORTED]: Package subpath \'./v4\' is not defined\nat x'}]})
    review = SimpleNamespace(package='tough-cookie', installed='2.5.0', target='4.1.3', status=FIX_PASSED, plan={},
                             reason='Тесты, сборка и запуск прошли', verification=None)
    result = agent_result()
    result.packages += [broken, review]
    manual = {m['package']: m for m in fix_set_from_agent(result).manual}
    assert 'ERR_PACKAGE_PATH_NOT_EXPORTED' in manual['uuid']['detail'] and 'не тот шаг' not in manual['uuid']['detail']
    assert 'просмотра человеком' in manual['tough-cookie']['reason'] and '2.5.0 -> 4.1.3' in manual['tough-cookie']['reason']
    body = build_pr_body(fix_set(manual=list(manual.values())))
    assert 'ошибка: Error ERR_PACKAGE_PATH_NOT_EXPORTED' in body and 'не включено' in body


def test_pr_body_shows_commit_and_readable_database_date():
    body = build_pr_body(fix_set(db_updated_at='2026-10-07T07:38:55.515026687Z'), SHA)
    assert f'`{SHA[:12]}`' in body and 'база CVE от 2026-10-07 07:38 UTC' in body and '515026687' not in body
    assert 'overrides' in body and 'вложенной' in body
    assert SHA[:12] not in build_pr_body(fix_set())


def test_created_pr_body_contains_the_verified_commit(hub, client):
    make(client)
    assert SHA[:12] in hub.calls('POST', '/pulls')[0]['body']['body']

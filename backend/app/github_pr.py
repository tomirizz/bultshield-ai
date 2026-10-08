"""Pull request с проверенным исправлением в учебном репозитории GitHub.

Правила безопасности:
- PR создаётся только после явного подтверждения (confirmed=True) и только в репозиторий из списка
  FIX_PR_ALLOWED_REPOS; по умолчанию список пуст, и создание PR выключено.
- Токен (GITHUB_FIX_TOKEN) нужен только этому модулю: он не попадает ни в ошибки, ни в журнал, ни в тело PR.
- Меняются только package.json и package-lock.json, и только если репозиторий на указанном коммите совпадает
  с тем, что проверяла песочница. Иначе PR не создаётся: результат проверки относится к другому коду.
- Слияния здесь нет: PR принимает человек. Повторный вызов с теми же данными возвращает уже открытый PR.
"""
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import quote

from .fix_agent import FIX_PASSED
from .scanner_catalog import TRIVY_VERSION

API = 'https://api.github.com'
ALLOWED_FILES = ('package.json', 'package-lock.json')
MAX_FILE = 5 * 1024 * 1024
MAX_RESPONSE = 6 * 1024 * 1024
_REPO = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}')
_BRANCH = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,100}')
_SHA = re.compile(r'[0-9a-f]{40}')
_PREFIX = re.compile(r'(?:[A-Za-z0-9._-]+/)*')
_TOKEN = re.compile(r'[A-Za-z0-9_\-]{20,255}')
_SAFE_TEXT = re.compile(r'[^\w@.,:;()«»/+~ -]', re.UNICODE)


class GitHubError(RuntimeError):
    """Запрос к GitHub не выполнен. Текст безопасен для показа: токена в нём нет."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class BaseMovedError(GitHubError):
    """Репозиторий уже не совпадает с проверенным кодом: PR не создаётся."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None   # заголовок Authorization не должен уйти на другой адрес


def allowed_repos():
    return {item.strip().lower() for item in os.environ.get('FIX_PR_ALLOWED_REPOS', '').split(',') if item.strip()}


def _default_opener(request, timeout):
    return urllib.request.build_opener(_NoRedirect).open(request, timeout=timeout)


class GitHubClient:
    def __init__(self, token, *, opener=None, timeout=20):
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            raise GitHubError('Токен GitHub не задан или имеет недопустимый вид.')
        self._token = token
        self._opener = opener or _default_opener
        self._timeout = timeout

    @classmethod
    def from_environment(cls, **kwargs):
        token = os.environ.get('GITHUB_FIX_TOKEN', '')
        if not token:
            raise GitHubError('Не задана переменная GITHUB_FIX_TOKEN: создание PR выключено.')
        return cls(token, **kwargs)

    def _scrub(self, text):
        return str(text).replace(self._token, '***')[:300]

    def request(self, method, path, body=None, *, raw=False):
        headers = {'Authorization': f'Bearer {self._token}', 'User-Agent': 'bultshield-security-agent',
                   'X-GitHub-Api-Version': '2022-11-28',
                   'Accept': 'application/vnd.github.raw+json' if raw else 'application/vnd.github+json'}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(API + path, data=data, method=method, headers=headers)
        try:
            with self._opener(request, self._timeout) as response:
                content = response.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            detail = ''
            try:
                detail = json.loads(exc.read(4096)).get('message', '')
            except (ValueError, AttributeError, OSError):
                pass
            hint = ' (проверьте права токена и список репозиториев)' if exc.code in (401, 403, 404) else ''
            raise GitHubError(f'GitHub вернул {exc.code}: {self._scrub(detail)}{hint}', exc.code) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise GitHubError(f'GitHub недоступен: {type(exc).__name__}.') from None
        if len(content) > MAX_RESPONSE:
            raise GitHubError('Ответ GitHub превышает лимит размера.')
        if raw:
            return content.decode('utf-8', 'replace')
        try:
            return json.loads(content) if content else {}
        except ValueError:
            raise GitHubError('Ответ GitHub не удалось разобрать.') from None


@dataclass
class FixSet:
    """Что именно попадёт в PR. Собирается из результата агента исправлений (fix_set_from_agent)."""
    packages: list                  # [{'package', 'from', 'to', 'method', 'resolves': [...]}]
    files: dict                     # итоговые package.json и package-lock.json
    original: dict                  # их исходное содержимое, проверенное песочницей
    manual: list = field(default_factory=list)   # [{'package', 'reason'}]: не вошло в PR
    db_updated_at: str | None = None


def fix_set_from_agent(result):
    """FixSet из AgentResult. Только если набор обновлений прошёл совместную проверку."""
    combined, raw = result.combined, result.combined_result
    if not combined or combined.get('outcome') != 'FIX_VERIFIED' or not getattr(raw, 'files', None):
        raise GitHubError('Нет набора обновлений, прошедшего совместную проверку: PR создавать не из чего.')
    chosen = {item.package: item for item in result.packages if item.package in combined['packages']}
    methods = {c['package']: c['method'] for c in combined.get('candidates', [])}
    packages = [{'package': name, 'from': item.installed, 'to': item.target, 'method': methods.get(name, ''),
                 'resolves': list(item.plan.get('resolves', []))} for name, item in chosen.items()]
    manual = [_manual_entry(i) for i in result.packages if i.package not in chosen]
    return FixSet(packages, dict(raw.files), dict(raw.original), manual, combined.get('scan_db_updated_at'))


def _error_line(verification):
    """Первая строка с ошибкой из лога шага, на котором остановилась проверка (для объяснения человеку)."""
    step = (verification or {}).get('failed_step')
    for entry in (verification or {}).get('steps', []):
        if entry.get('name') == step:
            for row in entry.get('log_tail', '').splitlines():
                if re.search(r'Error|ERR_|ERROR|not ok', row):
                    return row.strip()
    return ''


def _manual_entry(item):
    if item.status == FIX_PASSED:
        reason = (f'обновление {item.installed} -> {item.target} прошло проверку, но требует просмотра человеком '
                  '(меняет мажорную версию или закрывает не всё); в этот PR не включено')
        return {'package': item.package, 'reason': reason}
    return {'package': item.package, 'reason': item.reason, 'detail': _error_line(getattr(item, 'verification', None))}


def _date(text):
    match = re.match(r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})', str(text))
    return f'{match.group(1)} {match.group(2)} UTC' if match else _md(text, 40)


def _md(text, limit=300):
    """Текст для Markdown-таблиц: без разметки, переводов строк и посторонних символов."""
    text = re.sub(r'\S*://\S*', '[ссылка удалена]', str(text).replace('\n', ' '))   # GitHub превращает адреса в ссылки
    return _SAFE_TEXT.sub('', text)[:limit]


def build_pr_body(fix, base_sha=None):
    rows = ['| Пакет | Было | Стало | Способ | Закрывает |', '|---|---|---|---|---|']
    for item in fix.packages:
        how = {'direct': 'прямая зависимость', 'override': 'overrides (вложенная)'}.get(item['method'], item['method'])
        rows.append(f"| `{_md(item['package'])}` | {_md(item['from'])} | {_md(item['to'])} | {_md(how)} | "
                    f"{_md(', '.join(item['resolves']) or '-', 400)} |")
    lines = ['## Обновление уязвимых зависимостей', '', *rows, '',
             '`overrides` - поле в package.json, которое заставляет npm использовать указанную версию вложенной '
             'зависимости (той, что подтянул другой пакет).', '',
             '### Как проверено',
             f'Все обновления проверены **вместе** в изолированной песочнице (Docker): установка с `--ignore-scripts`, '
             f'тесты без сети, сборка образа, запуск без сети и проверка `/health`, затем повторный скан Trivy {TRIVY_VERSION}'
             f'{" (база CVE от " + _date(fix.db_updated_at) + ")" if fix.db_updated_at else ""}. '
             'Целевые находки исчезли, новых находок приложения не появилось.',
             *([f'Проверка выполнена для коммита `{base_sha[:12]}`.'] if base_sha else []), '',
             '### Что важно знать',
             '- Проверка выполнена на копии проекта. Образ не публиковался: пока образ не пересобран, опубликован и '
             'повторно просканирован, **работающее приложение не исправлено**.',
             '- Тесты проекта могут быть неполными: зелёные тесты не доказывают совместимость во всех сценариях.']
    if fix.manual:
        lines += ['', '### Не вошло в этот PR (нужен ручной разбор)']
        for m in fix.manual:
            lines.append(f"- `{_md(m['package'])}`: {_md(m['reason'])}")
            if m.get('detail'):
                lines.append(f"  - ошибка: {_md(m['detail'], 200)}")
    lines += ['', '---', 'Сформировано автоматически (BultShield). Слияние выполняет человек.']
    return '\n'.join(lines) + '\n'


def _branch_name(base_sha, files):
    digest = hashlib.sha256(json.dumps([base_sha, sorted(files.items())], ensure_ascii=False).encode()).hexdigest()
    return f'bultshield/fix-{digest[:10]}'


def _validate(repo, base_branch, base_sha, fix, project_path, allowed):
    if not isinstance(repo, str) or not _REPO.fullmatch(repo):
        raise GitHubError('Некорректное имя репозитория (нужно владелец/имя).')
    if repo.lower() not in (allowed_repos() if allowed is None else {a.lower() for a in allowed}):
        raise GitHubError('Репозиторий не входит в список разрешённых (настройка FIX_PR_ALLOWED_REPOS).')
    if (not isinstance(base_branch, str) or not _BRANCH.fullmatch(base_branch) or '..' in base_branch
            or base_branch.endswith(('/', '.lock'))):
        raise GitHubError('Некорректное имя базовой ветки.')
    if not isinstance(base_sha, str) or not _SHA.fullmatch(base_sha):
        raise GitHubError('Нужен полный 40-значный SHA коммита, для которого выполнена проверка.')
    if not isinstance(project_path, str) or not _PREFIX.fullmatch(project_path) or '..' in project_path.split('/'):
        raise GitHubError('Некорректный путь к проекту в репозитории.')
    if set(fix.files) != set(ALLOWED_FILES) or set(fix.original) != set(ALLOWED_FILES):
        raise GitHubError('В PR можно включить только package.json и package-lock.json.')
    if any(not isinstance(v, str) or not v or len(v.encode()) > MAX_FILE for v in fix.files.values()):
        raise GitHubError('Файл исправления пуст или превышает 5 МБ.')
    if fix.files == fix.original or not fix.packages:
        raise GitHubError('Исправление не меняет файлы: PR не нужен.')


def create_fix_pr(client, repo, *, base_branch, base_sha, fix, confirmed, project_path='', allowed=None, draft=False):
    """Создаёт ветку, один коммит и PR. Возвращает словарь с номером, адресом и признаком created."""
    if confirmed is not True:
        raise GitHubError('PR создаётся только после подтверждения человеком.')
    _validate(repo, base_branch, base_sha, fix, project_path, allowed)
    owner = repo.split('/')[0]
    git = f'/repos/{repo}/git'
    branch = _branch_name(base_sha, fix.files)

    existing = client.request('GET', f'/repos/{repo}/pulls?state=open&base={quote(base_branch, safe="")}'
                                     f'&head={quote(owner + ":" + branch, safe="")}')
    if isinstance(existing, list) and existing:
        pr = existing[0]
        return {'created': False, 'number': pr.get('number'), 'url': _html_url(pr), 'branch': branch}

    head = client.request('GET', f'{git}/ref/heads/{quote(base_branch, safe="/")}')
    current = (head.get('object') or {}).get('sha')
    if current != base_sha:
        raise BaseMovedError('Ветка уже ушла вперёд: проверка относится к другому коммиту. Запустите проверку заново.')
    for name in ALLOWED_FILES:
        path = quote(project_path + name, safe='/')
        actual = client.request('GET', f'/repos/{repo}/contents/{path}?ref={base_sha}', raw=True)
        if actual != fix.original[name]:
            raise BaseMovedError(f'Файл {name} в репозитории отличается от проверенного: PR не создан.')

    tree_base = (client.request('GET', f'{git}/commits/{base_sha}').get('tree') or {}).get('sha')
    entries = []
    for name in ALLOWED_FILES:
        blob = client.request('POST', f'{git}/blobs', {'content': fix.files[name], 'encoding': 'utf-8'})
        entries.append({'path': project_path + name, 'mode': '100644', 'type': 'blob', 'sha': blob.get('sha')})
    tree = client.request('POST', f'{git}/trees', {'base_tree': tree_base, 'tree': entries}).get('sha')
    names = ', '.join(_md(item['package']) for item in fix.packages)
    commit = client.request('POST', f'{git}/commits', {
        'message': f'BultShield: update vulnerable dependencies ({names})\n\nVerified together in an isolated sandbox.',
        'tree': tree, 'parents': [base_sha]}).get('sha')
    _create_branch(client, git, branch, commit, tree)

    pr = client.request('POST', f'/repos/{repo}/pulls', {
        'title': f'Обновить уязвимые зависимости: {names}'[:200], 'head': branch, 'base': base_branch,
        'body': build_pr_body(fix, base_sha), 'draft': bool(draft), 'maintainer_can_modify': False})
    return {'created': True, 'number': pr.get('number'), 'url': _html_url(pr), 'branch': branch, 'commit': commit}


def _create_branch(client, git, branch, commit, tree):
    try:
        client.request('POST', f'{git}/refs', {'ref': f'refs/heads/{branch}', 'sha': commit})
    except GitHubError as exc:
        if exc.status != 422:
            raise
        # Ветка осталась от прерванного запуска: годится, только если в ней ровно то же дерево файлов.
        ref = client.request('GET', f'{git}/ref/heads/{quote(branch, safe="/")}')
        sha = (ref.get('object') or {}).get('sha')
        if (client.request('GET', f'{git}/commits/{sha}').get('tree') or {}).get('sha') != tree:
            raise GitHubError(f'Ветка {branch} уже существует с другим содержимым. Удалите её и повторите.') from None


def _html_url(pr):
    url = pr.get('html_url')
    if not isinstance(url, str) or not url.startswith('https://github.com/'):
        raise GitHubError('GitHub вернул неожиданный адрес PR.')
    return url


def fetch_pull_request(client, repo, number, *, allowed=None):
    """Состояние PR на GitHub: слит ли он, когда и каким коммитом. Только чтение, ничего не меняет."""
    if not isinstance(repo, str) or not _REPO.fullmatch(repo):
        raise GitHubError('Некорректное имя репозитория (нужно владелец/имя).')
    if repo.lower() not in (allowed_repos() if allowed is None else {a.lower() for a in allowed}):
        raise GitHubError('Репозиторий не входит в список разрешённых (настройка FIX_PR_ALLOWED_REPOS).')
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise GitHubError('Некорректный номер PR.')
    pr = client.request('GET', f'/repos/{repo}/pulls/{number}')
    if not isinstance(pr, dict) or pr.get('number') != number:
        raise GitHubError('GitHub вернул не тот PR, который запрашивали.')
    base, head = pr.get('base') or {}, pr.get('head') or {}
    merged = pr.get('merged') is True
    merge_sha, merged_at = pr.get('merge_commit_sha'), pr.get('merged_at')
    if merged and (not isinstance(merge_sha, str) or not _SHA.fullmatch(merge_sha) or not isinstance(merged_at, str)):
        raise GitHubError('GitHub сообщил о слиянии без коммита или времени слияния: считать PR слитым нельзя.')
    return {'number': number, 'state': pr.get('state'), 'merged': merged, 'merged_at': merged_at if merged else None,
            'merge_commit_sha': merge_sha if merged else None, 'head_ref': head.get('ref'), 'base_ref': base.get('ref'),
            'url': _html_url(pr)}

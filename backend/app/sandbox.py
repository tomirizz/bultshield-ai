"""Изолированная проверка исправления зависимости в Docker.

Порядок: копия проекта -> `npm install` (сеть открыта, скрипты пакетов отключены) -> тесты без сети ->
сборка образа -> запуск без сети и проверка /health -> `docker save` -> повторный скан Trivy.
Исходный проект не меняется: все действия идут в копии. Неопределённый результат (нет Docker, таймаут,
сбой сканера) никогда не выдаётся за «исправление подтверждено».

Ограничения первой версии: Node.js/npm; прямые зависимости обновляются через `npm install пакет@версия`,
транзитивные (их подтягивает другой пакет) — через поле `overrides` в package.json; образ приложения должен
содержать Node.js (проверка /health идёт командой `node` внутри контейнера). Dockerfile проекта
считается недоверенным кодом только условно: сборка идёт с сетью, поэтому проект должен быть учебным.
"""
import difflib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from .image_scan import ImageScanError, run_archive_scan

FIX_VERIFIED = 'FIX_VERIFIED'        # тесты, сборка, запуск прошли, целевые находки исчезли
STILL_DETECTED = 'STILL_DETECTED'    # приложение работает, но целевые находки остались
NEW_FINDINGS = 'NEW_FINDINGS'        # целевые находки исчезли, но обновление принесло новые
BREAKS_APP = 'BREAKS_APP'            # обновление ломает установку, тесты, сборку или запуск
INCONCLUSIVE = 'INCONCLUSIVE'        # проверить не удалось: это не «чисто» и не «сломано»
OUTCOMES = (FIX_VERIFIED, STILL_DETECTED, NEW_FINDINGS, BREAKS_APP, INCONCLUSIVE)

# Первый символ — буква или цифра: имя не может начинаться с «-» и сойти за параметр npm.
_PACKAGE = re.compile(r'(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*')
_VERSION = re.compile(r'\d+\.\d+\.\d+')
_IMAGE = re.compile(r'[a-z0-9][a-z0-9._/-]{0,100}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?')
_PLATFORM = re.compile(r'[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9]+)?')
_HEALTH_PATH = re.compile(r'/[A-Za-z0-9/_.-]{0,100}')
_NETWORK_TROUBLE = re.compile(
    r'ETIMEDOUT|ENOTFOUND|EAI_AGAIN|ECONNRESET|ECONNREFUSED|socket hang up|fetch failed|failed to fetch'
    r'|\bTLS\b|i/o timeout|no such host|toomanyrequests|temporary failure|Cannot connect to the Docker daemon', re.I)
_PLACEHOLDER_TEST = re.compile(r'no test specified', re.I)
TAIL = 1500
DIFF_LIMIT = 60_000
LIMITS = ['--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256']


@dataclass(frozen=True)
class SandboxConfig:
    node_image: str = 'node:24-slim'
    platform: str = 'linux/amd64'
    port: int = 3000
    health_path: str = '/health'
    install_timeout: int = 300
    test_timeout: int = 180
    build_timeout: int = 600
    health_timeout: int = 30
    save_timeout: int = 180
    work_root: Path | None = None   # по умолчанию ~/.cache/bultshield-sandbox (внутри домашней папки: её Docker на Mac видит)

    def __post_init__(self):
        if not _IMAGE.fullmatch(self.node_image) or not _PLATFORM.fullmatch(self.platform):
            raise ValueError('Некорректный образ или платформа песочницы.')
        if not 1 <= self.port <= 65535 or not _HEALTH_PATH.fullmatch(self.health_path):
            raise ValueError('Некорректный порт или путь проверки здоровья.')


@dataclass(frozen=True)
class FixCandidate:
    package: str            # имя npm-пакета
    target: str             # версия, на которую обновляем, вида 4.18.1
    resolves: tuple = ()    # идентификаторы находок (CVE...), которые обновление должно закрыть; пусто = все по пакету

    def __post_init__(self):
        if not _PACKAGE.fullmatch(self.package) or len(self.package) > 214 or not _VERSION.fullmatch(self.target):
            raise ValueError('Некорректное имя пакета или версия.')


@dataclass
class SandboxResult:
    outcome: str
    reason: str
    failed_step: str | None = None
    steps: list = field(default_factory=list)
    diff: str = ''
    resolved: list = field(default_factory=list)
    remaining: list = field(default_factory=list)
    introduced: list = field(default_factory=list)
    scan_db_updated_at: str | None = None
    method: str = ''   # 'direct' (npm install пакет@версия), 'override' (поле overrides) или 'mixed'
    candidates: list = field(default_factory=list)   # [{'package', 'target', 'method'}]
    files: dict = field(default_factory=dict)        # итоговое содержимое package.json и package-lock.json; только при FIX_VERIFIED
    original: dict = field(default_factory=dict)     # исходное содержимое тех же файлов: PR сверяет с ним репозиторий

    def as_dict(self):
        data = {key: getattr(self, key) for key in (
            'outcome', 'reason', 'failed_step', 'steps', 'diff', 'resolved', 'remaining', 'introduced',
            'scan_db_updated_at', 'method', 'candidates')}
        data['files'] = sorted(self.files)   # сами файлы большие и отдаются отдельно через .files
        return data


@dataclass(frozen=True)
class _Command:
    code: int | None        # None = таймаут
    tail: str
    seconds: float


class _Stop(Exception):
    """Проверка закончена досрочно с готовым результатом."""

    def __init__(self, result):
        self.result = result


def _clean(data):
    text = data.decode('utf-8', 'replace')
    text = ''.join(ch for ch in text if ch == '\n' or ch == '\t' or ord(ch) >= 32)
    return text.strip()[-TAIL:]


def _environment():
    keep = ('PATH', 'HOME', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG')
    return {key: os.environ[key] for key in keep if key in os.environ}


def _execute(command, timeout, directory):
    """Запуск одного процесса с лимитом времени. Вывод читается только с конца и ограничен."""
    log = directory / f'cmd-{uuid.uuid4().hex[:8]}.log'
    started = time.monotonic()
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                   env=_environment(), start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = None
    with log.open('rb') as handle:
        handle.seek(0, os.SEEK_END)
        handle.seek(max(0, handle.tell() - 8192))
        tail = _clean(handle.read())
    log.unlink(missing_ok=True)
    return _Command(code, tail, round(time.monotonic() - started, 1))


def _diff(before, after):
    parts = []
    for name in sorted(before):
        old, new = before[name].splitlines(keepends=True), after.get(name, '').splitlines(keepends=True)
        parts.extend(difflib.unified_diff(old, new, f'a/{name}', f'b/{name}'))
    text = ''.join(parts)
    return text if len(text) <= DIFF_LIMIT else text[:DIFF_LIMIT] + '\n... diff обрезан ...\n'


def _pack(items):
    return [{'rule_id': rule, 'package': package} for rule, package in items]


def _keys(findings):
    return {(f['rule_id'], f['package']) for f in findings if f.get('origin') == 'app'}


def _in_lock(lock_text, package):
    """Есть ли пакет среди установленных по package-lock.json (lockfileVersion 2/3)."""
    try:
        entries = json.loads(lock_text).get('packages')
    except ValueError:
        return None
    if not isinstance(entries, dict):
        return None
    return any(key == f'node_modules/{package}' or key.endswith(f'/node_modules/{package}') for key in entries)


def _with_override(text, package, version):
    """package.json с добавленным overrides[package] = version. Отступ исходного файла сохраняется."""
    data = json.loads(text)
    overrides = data.get('overrides', {})
    if not isinstance(overrides, dict) or isinstance(overrides.get(package), dict):
        raise ValueError('overrides имеет вложенный вид, который первая версия не меняет')
    overrides[package] = version
    data['overrides'] = overrides
    indent = re.search(r'^( +|\t)"', text, re.M)
    return json.dumps(data, indent=indent.group(1) if indent else '  ', ensure_ascii=False) + '\n'


def _read_manifest(project):
    manifest, lock = project / 'package.json', project / 'package-lock.json'
    if not manifest.is_file() or not lock.is_file():
        return None, 'В проекте нет package.json или package-lock.json: без lock-файла результат не воспроизводим.'
    try:
        data = json.loads(manifest.read_text())
    except (OSError, ValueError):
        return None, 'package.json не удалось прочитать.'
    if not isinstance(data, dict):
        return None, 'package.json имеет неожиданный вид.'
    return data, None


MAX_CANDIDATES = 10


def verify_fix(project_dir, candidate, baseline, *, config=None, scan=run_archive_scan):
    """Проверяет одно обновление `candidate` в копии проекта. `baseline` — находки исходного образа."""
    return verify_fixes(project_dir, [candidate], baseline, config=config, scan=scan)


def verify_fixes(project_dir, candidates, baseline, *, config=None, scan=run_archive_scan):
    """Проверяет несколько обновлений вместе, как будущий один PR: одна копия, одна сборка, один повторный скан."""
    candidates = list(candidates)
    if not 1 <= len(candidates) <= MAX_CANDIDATES or len({c.package for c in candidates}) != len(candidates):
        raise ValueError(f'Нужно от 1 до {MAX_CANDIDATES} обновлений, каждый пакет не более одного раза.')
    config = config or SandboxConfig()
    steps = []
    try:
        return _verify(Path(project_dir), candidates, baseline, config, scan, steps)
    except _Stop as stop:
        stop.result.steps = steps
        return stop.result


def _stop(outcome, reason, step=None, **extra):
    raise _Stop(SandboxResult(outcome, reason, step, **extra))


def _verify(project, candidates, baseline, config, scan, steps):
    if not project.is_dir():
        _stop(INCONCLUSIVE, 'Папка проекта не найдена.')
    manifest, problem = _read_manifest(project)
    if problem:
        _stop(INCONCLUSIVE, problem)
    declared = {**(manifest.get('devDependencies') or {}), **(manifest.get('dependencies') or {})}
    methods = {}
    for candidate in candidates:
        methods[candidate.package] = 'direct'
        if candidate.package not in declared:
            methods[candidate.package] = 'override'
            found = _in_lock((project / 'package-lock.json').read_text(), candidate.package)
            if found is None:
                _stop(INCONCLUSIVE, 'package-lock.json старого формата или повреждён: транзитивную зависимость нельзя найти.')
            if not found:
                _stop(INCONCLUSIVE, f'Пакета {candidate.package} нет ни в package.json, ни в package-lock.json: '
                                    'обновлять нечего.')
    test_script = (manifest.get('scripts') or {}).get('test')
    if not isinstance(test_script, str) or _PLACEHOLDER_TEST.search(test_script):
        _stop(INCONCLUSIVE, 'В проекте нет настоящего скрипта test: исправление нельзя проверить тестами.')
    targeted = set()
    for candidate in candidates:
        found = {(f['rule_id'], f['package']) for f in baseline
                 if f.get('origin') == 'app' and f['package'] == candidate.package
                 and (not candidate.resolves or f['rule_id'] in candidate.resolves)}
        if not found:
            _stop(INCONCLUSIVE, f'В исходном отчёте нет находок по пакету {candidate.package}: проверять нечего.')
        targeted |= found
    docker = shutil.which('docker')
    if not docker:
        _stop(INCONCLUSIVE, 'Docker не установлен: изолированная проверка невозможна на этом компьютере.')

    root = config.work_root or Path.home() / '.cache' / 'bultshield-sandbox'
    root.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:10]
    containers = [f'bultshield-sbx-{run_id}-{name}' for name in ('install', 'test', 'app')]
    tag = f'bultshield-sbx:{run_id}'
    with TemporaryDirectory(prefix='run-', dir=root, ignore_cleanup_errors=True) as temporary:
        base = Path(temporary).resolve()
        work, logs, archive = base / 'project', base / 'logs', base / 'image.tar'
        logs.mkdir()
        shutil.copytree(project, work, symlinks=True, ignore=shutil.ignore_patterns('.git', 'node_modules'))
        if not (work / '.dockerignore').exists():
            # Контекст сборки без node_modules и .git: меньше данных, и в образ не попадёт ничего с хоста.
            (work / '.dockerignore').write_text('node_modules\n.git\n')
        before = {name: (work / name).read_text() for name in ('package.json', 'package-lock.json')}
        try:
            return _pipeline(docker, work, logs, archive, tag, containers, candidates, targeted, baseline,
                             before, config, scan, steps)
        except _Stop as stop:
            kinds = set(methods.values())
            stop.result.method = kinds.pop() if len(kinds) == 1 else 'mixed'
            stop.result.candidates = [{'package': c.package, 'target': c.target, 'method': methods[c.package]}
                                      for c in candidates]
            raise
        finally:
            for name in containers:
                _execute([docker, 'rm', '-f', name], 30, logs)
            _execute([docker, 'rmi', '-f', tag], 30, logs)


def _step(name, command, timeout, logs, steps):
    result = _execute(command, timeout, logs)
    status = 'timeout' if result.code is None else 'passed' if result.code == 0 else 'failed'
    steps.append({'name': name, 'status': status, 'seconds': result.seconds, 'log_tail': result.tail})
    return result


def _fail(result, step, what, uses_network=True, note=''):
    """Сбой шага: таймаут и проблемы сети — неопределённо, остальное — обновление ломает приложение."""
    if result.code is None:
        _stop(INCONCLUSIVE, f'Шаг «{what}» превысил лимит времени: причина неизвестна, нужна ручная проверка.', step)
    if uses_network and _NETWORK_TROUBLE.search(result.tail):
        _stop(INCONCLUSIVE, f'Шаг «{what}» не удался из-за сети или Docker: это не вина обновления. '
                            f'Повторите проверку.', step)
    _stop(BREAKS_APP, f'Шаг «{what}» завершился с ошибкой после обновления (код {result.code}).{note}', step)


def _pipeline(docker, work, logs, archive, tag, containers, candidates, targeted, baseline, before, config, scan, steps):
    install_name, test_name, app_name = containers
    info = _step('docker', [docker, 'info'], 30, logs, steps)
    if info.code != 0:
        _stop(INCONCLUSIVE, 'Демон Docker недоступен (не запущен Docker Desktop?): изолированная проверка не выполнена.', 'docker')
    user = ['--user', f'{os.getuid()}:{os.getgid()}'] if sys.platform.startswith('linux') else []
    common = ['--platform', config.platform, '-v', f'{work}:/work', '-w', '/work', '-e', 'HOME=/tmp',
              *LIMITS, '--memory', '512m', '--cpus', '1', *user]

    declared = {**(json.loads(before['package.json']).get('devDependencies') or {}),
                **(json.loads(before['package.json']).get('dependencies') or {})}
    direct = [c for c in candidates if c.package in declared]
    # Транзитивные зависимости: пишем overrides в package.json, затем npm пересобирает lock-файл.
    text = before['package.json']
    try:
        for candidate in candidates:
            if candidate.package not in declared:
                text = _with_override(text, candidate.package, candidate.target)
    except ValueError as exc:
        _stop(INCONCLUSIVE, f'Не удалось добавить overrides: {exc}. Нужен ручной разбор.', 'install')
    if text != before['package.json']:
        (work / 'package.json').write_text(text)
    arguments = ['--ignore-scripts', '--no-audit', '--no-fund']
    if direct:
        arguments = ['--save-exact', *arguments, *(f'{c.package}@{c.target}' for c in direct)]
    install = [docker, 'run', '--rm', '--name', install_name, *common, config.node_image, 'npm', 'install', *arguments]
    result = _step('install', install, config.install_timeout, logs, steps)
    if result.code != 0:
        _fail(result, 'install', 'установка обновлённой версии')
    after = {name: (work / name).read_text() for name in before}
    diff = _diff(before, after)
    if after == before:
        _stop(INCONCLUSIVE, 'Установка не изменила package.json и package-lock.json: обновление не применилось.', 'install')
    if after['package-lock.json'] == before['package-lock.json']:
        _stop(INCONCLUSIVE, 'После установки package-lock.json не изменился: npm не применил обновление. '
                            'Нужен ручной разбор.', 'install', diff=diff)

    # Тесты запускаются без сети: проект, как и его зависимости, не может ничего отправить наружу.
    test = [docker, 'run', '--rm', '--name', test_name, '--network', 'none', *common, config.node_image, 'npm', 'test']
    result = _step('tests', test, config.test_timeout, logs, steps)
    if result.code != 0:
        _fail_with_diff(result, 'tests', 'тесты', diff, uses_network=False,
                        note=' Тесты шли без сети и до обновления не запускались: причина может быть и в самих тестах.')

    build = [docker, 'build', '--platform', config.platform, '-q', '-t', tag, str(work)]
    result = _step('build', build, config.build_timeout, logs, steps)
    if result.code != 0:
        _fail_with_diff(result, 'build', 'сборка образа', diff)

    start = [docker, 'run', '-d', '--platform', config.platform, '--name', app_name, '--network', 'none',
             '--memory', '256m', '--cpus', '1', '--pids-limit', '128', '--cap-drop', 'ALL',
             '--security-opt', 'no-new-privileges', '--read-only', tag]
    result = _step('start', start, 60, logs, steps)
    if result.code != 0:
        _fail_with_diff(result, 'start', 'запуск приложения', diff, uses_network=False)
    _health(docker, app_name, config, logs, steps, diff)

    result = _step('save', [docker, 'save', tag, '-o', str(archive)], config.save_timeout, logs, steps)
    if result.code != 0:
        _stop(INCONCLUSIVE, 'Не удалось сохранить образ для повторного скана.', 'save', diff=diff)

    started = time.monotonic()
    try:
        rescan = scan(archive)
    except ImageScanError as exc:
        steps.append({'name': 'rescan', 'status': 'failed', 'seconds': round(time.monotonic() - started, 1),
                      'log_tail': str(exc)[:TAIL]})
        _stop(INCONCLUSIVE, f'Повторный скан не выполнен: {exc} Это не означает, что уязвимостей нет.', 'rescan', diff=diff)
    steps.append({'name': 'rescan', 'status': 'passed', 'seconds': round(time.monotonic() - started, 1), 'log_tail': ''})

    packages = rescan.report.summary.get('packages') or []
    missing = [f'{c.package} {c.target}' for c in candidates
               if not any(p['name'] == c.package and p['version'] == c.target and p['origin'] == 'app' for p in packages)]
    if missing:
        _stop(INCONCLUSIVE, f"В пересобранном образе Trivy не нашёл среди пакетов приложения: {', '.join(missing)}. "
                            'Нельзя утверждать, что скан увидел приложение. Пустой список находок не принят за «чисто».',
              'rescan', diff=diff, scan_db_updated_at=rescan.db_updated_at)

    now = _keys(rescan.report.findings)
    remaining = sorted(targeted & now)
    resolved = sorted(targeted - now)
    introduced = sorted(now - _keys(baseline))
    extra = dict(diff=diff, resolved=_pack(resolved), remaining=_pack(remaining), introduced=_pack(introduced),
                 scan_db_updated_at=rescan.db_updated_at)
    if remaining:
        _stop(STILL_DETECTED, f'Приложение работает, но {len(remaining)} из {len(targeted)} целевых находок остались '
                              'в пересобранном образе: обновление их не закрыло.', None, **extra)
    if introduced:
        _stop(NEW_FINDINGS, f'Целевые находки закрыты, но обновление принесло новых находок приложения: {len(introduced)}. '
                            'Нужен ручной разбор.', None, **extra)
    _stop(FIX_VERIFIED, f'Тесты, сборка и запуск прошли; все {len(targeted)} целевых находок исчезли после повторного скана. '
                        'Образ пересобран локально и не опубликован: приложение в эксплуатации не исправлено.', None,
          files=after, original=before, **extra)


def _fail_with_diff(result, step, what, diff, uses_network=True, note=''):
    try:
        _fail(result, step, what, uses_network, note)
    except _Stop as stop:
        stop.result.diff = diff
        raise


def _health(docker, name, config, logs, steps, diff):
    script = (f"fetch('http://127.0.0.1:{config.port}{config.health_path}')"
              ".then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))")
    deadline = time.monotonic() + config.health_timeout
    started = time.monotonic()
    last = None
    while True:
        running = _execute([docker, 'inspect', '-f', '{{.State.Running}}', name], 15, logs)
        if running.code == 0 and running.tail.strip() != 'true':
            break
        last = _execute([docker, 'exec', name, 'node', '-e', script], 15, logs)
        if last.code == 0:
            steps.append({'name': 'health', 'status': 'passed', 'seconds': round(time.monotonic() - started, 1),
                          'log_tail': ''})
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(1)
    tail = _execute([docker, 'logs', '--tail', '20', name], 15, logs).tail
    steps.append({'name': 'health', 'status': 'failed', 'seconds': round(time.monotonic() - started, 1), 'log_tail': tail})
    _stop(BREAKS_APP, f'Приложение не ответило на {config.health_path} после обновления (или завершилось сразу после запуска).',
          'health', diff=diff)

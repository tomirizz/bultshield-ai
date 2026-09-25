import json
import os
import shutil
import signal
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .gitleaks_runner import GitleaksError, _check_size
from .scan_runtime import inherited_lock, temporary_directory, timeout_seconds
from .scanner_catalog import RULES, RULES_PATH, SEMGREP_VERSION

EXTENSIONS = {'.py', '.pyi', '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'}
EXCLUDED_DIRECTORIES = {'.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__', 'dist', 'build'}


class SemgrepError(RuntimeError):
    """Safe error text; never includes source, subprocess output or JSON excerpts."""


@dataclass(frozen=True)
class SemgrepReport:
    findings: list[dict]
    scanned_files: int


def _snapshot(repository: Path, target: Path) -> int:
    """Copy supported sources without repository-controlled configuration or symlinks."""
    count = 0
    target.mkdir()
    for directory, folders, files in os.walk(repository):
        folders[:] = sorted(name for name in folders if name not in EXCLUDED_DIRECTORIES
                            and not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink() or path.suffix.lower() not in EXTENSIONS or not path.is_file():
                continue
            count += 1
            if count > 5000:
                raise SemgrepError('Semgrep: превышен лимит 5000 исходных файлов.')
            destination = target / path.relative_to(repository)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
    # Override Semgrep defaults, which otherwise omit tests and fixtures.
    (target / '.semgrepignore').write_text('', encoding='utf-8')
    return count


def _relative_path(filename, repository):
    if not isinstance(filename, str) or not filename or len(filename) > 4096:
        raise SemgrepError('Некорректный путь Semgrep.')
    path = Path(filename)
    if not path.is_absolute():
        path = repository / path
    try:
        relative = path.resolve().relative_to(repository).as_posix()
    except (ValueError, OSError):
        raise SemgrepError('Semgrep вернул путь вне репозитория.') from None
    if len(relative) > 2048 or not path.is_file() or path.is_symlink():
        raise SemgrepError('Некорректный файл в отчёте Semgrep.')
    return relative


def parse_semgrep_report(data, repository: Path, expected_files: int) -> SemgrepReport:
    repository = repository.resolve()
    if not isinstance(data, dict) or not isinstance(data.get('results'), list) or not isinstance(data.get('errors'), list):
        raise SemgrepError('Некорректный JSON-отчёт Semgrep.')
    if data.get('version') != SEMGREP_VERSION:
        raise SemgrepError('Версия отчёта Semgrep не совпадает с установленной политикой.')
    if data['errors']:
        raise SemgrepError('Semgrep не проверил все файлы: ошибка разбора, памяти или тайм-аут. Результат неполный.')
    paths = data.get('paths')
    scanned = paths.get('scanned') if isinstance(paths, dict) else None
    if not isinstance(scanned, list):
        raise SemgrepError('Semgrep не указал список проверенных файлов.')
    scanned_set = {_relative_path(path, repository) for path in scanned}
    if len(scanned_set) != expected_files:
        raise SemgrepError('Semgrep пропустил часть исходных файлов. Результат неполный.')
    results = []
    for item in data['results']:
        if not isinstance(item, dict) or item.get('check_id') not in RULES:
            raise SemgrepError('Неизвестное правило в отчёте Semgrep.')
        filename = _relative_path(item.get('path'), repository)
        if filename not in scanned_set:
            raise SemgrepError('Находка Semgrep не относится к проверенным файлам.')
        positions = {}
        for key in ('start', 'end'):
            position = item.get(key)
            if not isinstance(position, dict):
                raise SemgrepError('Некорректная позиция Semgrep.')
            for field in ('line', 'col'):
                value = position.get(field)
                if type(value) is not int or not 0 < value <= 2_147_483_647:
                    raise SemgrepError('Некорректная позиция Semgrep.')
                positions[f'{key}_{field}'] = value
        if (positions['end_line'], positions['end_col']) < (positions['start_line'], positions['start_col']):
            raise SemgrepError('Некорректный диапазон Semgrep.')
        # No lines, metavars, interpolated messages, fixes or raw metadata leave this parser.
        results.append({'rule_id': item['check_id'], 'file': filename, **positions})
    return SemgrepReport(results, len(scanned_set))


def _run(command, workspace, environment):
    process = subprocess.Popen(
        command, cwd=workspace, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, pass_fds=inherited_lock(),
    )
    try:
        return process.wait(timeout=timeout_seconds("SEMGREP_TIMEOUT_SECONDS", 300))
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise SemgrepError('Semgrep превысил лимит времени.') from None


def run_semgrep(repository: Path) -> SemgrepReport:
    repository = repository.resolve()
    executable = shutil.which('semgrep')
    if executable is None:
        raise SemgrepError('Semgrep не установлен в worker.')
    if not repository.is_dir():
        raise SemgrepError('Папка репозитория не найдена.')
    try:
        _check_size(repository)
        with temporary_directory(prefix='bultshield-semgrep-') as temporary:
            workspace = Path(temporary)
            snapshot = workspace / 'source'
            expected = _snapshot(repository, snapshot)
            if expected == 0:
                return SemgrepReport([], 0)
            report = workspace / 'report.json'
            command = [
                executable, 'scan', '--oss-only', '--config', str(RULES_PATH),
                '--json', '--output', str(report), '--metrics=off', '--disable-version-check',
                '--no-rewrite-rule-ids', '--disable-nosem', '--no-git-ignore',
                '--no-autofix', '--jobs', '1',
                '--max-memory', '256', '--timeout', '5', '--timeout-threshold', '1',
                '--max-target-bytes', str(2 * 1024 * 1024), '--strict', '--quiet', '.',
            ]
            environment = {
                'PATH': os.pathsep.join([str(Path(executable).parent), os.defpath]),
                'HOME': str(workspace), 'LANG': 'C.UTF-8',
                'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0',
                'SEMGREP_SETTINGS_FILE': str(workspace / 'settings.yml'),
                'XDG_CONFIG_HOME': str(workspace), 'TMPDIR': str(workspace),
            }
            returncode = _run(command, snapshot, environment)
            if returncode != 0:
                raise SemgrepError(f'Semgrep завершился с ошибкой ({returncode}); проверка неполная.')
            if not report.is_file() or report.stat().st_size > 10 * 1024 * 1024:
                raise SemgrepError('JSON Semgrep отсутствует или превышает 10 МБ.')
            return parse_semgrep_report(json.loads(report.read_text(encoding='utf-8')), snapshot, expected)
    except GitleaksError as exc:
        raise SemgrepError(str(exc)) from None
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SemgrepError('Не удалось прочитать файлы или отчёт Semgrep.') from None

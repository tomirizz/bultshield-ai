"""Bounded dependency and configuration scans with no repository-controlled policy."""
import json
import os
import re
import shutil
import signal
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory, gettempdir

from .gitleaks_runner import GitleaksError, _check_size
from .scanner_catalog import TRIVY_VERSION
from .semgrep_runner import EXCLUDED_DIRECTORIES

# Explicit MVP scope: no binaries, archives, installed environments or package installation.
DEPENDENCY_FILES = {
    'requirements.txt', 'Pipfile.lock', 'poetry.lock', 'uv.lock', 'pyproject.toml',
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'package.json',
    'go.mod', 'go.sum', 'Cargo.lock', 'Gemfile.lock', 'composer.lock',
}
SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'}
MAX_REPORT = 20 * 1024 * 1024


class TrivyError(RuntimeError):
    """Safe diagnostics only; raw JSON/logs never leave the temporary workspace."""


@dataclass(frozen=True)
class TrivyReport:
    findings: list[dict]
    summary: dict


def _text(value, limit=300, required=True):
    if value is None and not required:
        return None
    if not isinstance(value, str) or len(value) > limit or (required and not value) or any(ord(c) < 32 for c in value):
        raise TrivyError('Некорректное поле в JSON Trivy.')
    return value


def _snapshot(repository, target):
    target.mkdir()
    files = set()
    for directory, folders, names in os.walk(repository):
        folders[:] = sorted(n for n in folders if n not in EXCLUDED_DIRECTORIES and not (Path(directory) / n).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            supported = (name in DEPENDENCY_FILES or name.startswith('requirements') and path.suffix == '.txt'
                         or name == 'Dockerfile' or name.startswith('Dockerfile.') or name.endswith('.Dockerfile')
                         or path.suffix in {'.yaml', '.yml'})
            if not supported or name in {'trivy.yaml', 'trivy.yml', 'trivy-secret.yaml'} or path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(repository).as_posix()
            if len(relative) > 2048 or any(ord(c) < 32 for c in relative):
                raise TrivyError('Trivy: неподдерживаемое имя файла.')
            files.add(relative)
            if len(files) > 5000:
                raise TrivyError('Trivy: превышен лимит 5000 файлов.')
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            # Disable full-line scanner directives without moving source line numbers.
            # Inline directives are rejected rather than editing a potential YAML value.
            content = path.read_bytes()
            content = re.sub(rb'(?m)^[ \t]*#[ \t]*(?:trivy|tfsec):ignore:[^\r\n]*', b'# BultShield: repository ignore disabled', content)
            if re.search(rb'(?:trivy|tfsec):ignore:', content):
                raise TrivyError('Trivy: встроенные inline-исключения не поддерживаются; проверка не выполнена.')
            destination.write_bytes(content)
    return files


def parse_trivy_report(data, allowed_files):
    if not isinstance(data, dict) or data.get('SchemaVersion') != 2 or data.get('ArtifactType') != 'filesystem':
        raise TrivyError('Неподдерживаемая схема JSON Trivy.')
    if not isinstance(data.get('Trivy'), dict) or data['Trivy'].get('Version') != TRIVY_VERSION:
        raise TrivyError('Версия отчёта Trivy не совпадает с установленной политикой.')
    results = data.get('Results', [])
    if results is None:
        results = []
    if not isinstance(results, list):
        raise TrivyError('Некорректный список результатов Trivy.')
    findings = []
    counts = {'dependency': 0, 'configuration': 0}
    targets = set()
    for result in results:
        if not isinstance(result, dict):
            raise TrivyError('Некорректный результат Trivy.')
        filename = _text(result.get('Target'), 2048)
        if filename not in allowed_files:
            raise TrivyError('Trivy вернул файл вне проверенной области.')
        targets.add(filename)
        kind = result.get('Class')
        if kind not in {'lang-pkgs', 'config'}:
            raise TrivyError('Trivy вернул неподдерживаемый тип результата.')
        ecosystem = _text(result.get('Type'), 100)
        for key, category in [('Vulnerabilities', 'dependency'), ('Misconfigurations', 'configuration')]:
            items = result.get(key)
            if items is None:
                items = []
            if not isinstance(items, list) or items and kind != ('lang-pkgs' if category == 'dependency' else 'config'):
                raise TrivyError('Некорректная категория Trivy.')
            for item in items:
                if not isinstance(item, dict):
                    raise TrivyError('Некорректная находка Trivy.')
                if category == 'configuration':
                    status = item.get('Status')
                    if status == 'PASS':
                        continue
                    if status not in {'FAIL', 'EXCEPTION'}:
                        raise TrivyError('Неизвестный статус проверки Trivy.')
                severity = _text(item.get('Severity'), 50)
                if severity not in SEVERITIES:
                    raise TrivyError('Неизвестный уровень риска Trivy.')
                rule = _text(item.get('VulnerabilityID' if category == 'dependency' else 'ID'), 64)
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', rule):
                    raise TrivyError('Некорректный идентификатор Trivy.')
                finding = dict(category=category, file=filename, rule_id=rule, severity=severity,
                               ecosystem=ecosystem, line_start=None, line_end=None)
                if category == 'dependency':
                    finding.update(package=_text(item.get('PkgName'), 512),
                                   installed_version=_text(item.get('InstalledVersion'), 300),
                                   fixed_version=_text(item.get('FixedVersion', ''), 1000, required=False) or None,
                                   package_id=_text(item.get('PkgID'), 1000, required=False),
                                   cve=rule if re.fullmatch(r'CVE-\d{4}-\d{4,}', rule) else None)
                else:
                    cause = item.get('CauseMetadata') or {}
                    if not isinstance(cause, dict):
                        raise TrivyError('Некорректное расположение Trivy.')
                    start, end = cause.get('StartLine', 0), cause.get('EndLine', 0)
                    if any(type(n) is not int or n < 0 or n > 2_147_483_647 for n in (start, end)) or end < start:
                        raise TrivyError('Некорректный диапазон строк Trivy.')
                    finding.update(line_start=start or None, line_end=(end or start) if start else None,
                                   suppressed=status == 'EXCEPTION')
                # Do not persist Message, Description, Code, URLs, metadata or raw source.
                findings.append(finding)
                counts[category] += 1
    return TrivyReport(findings, {'result_files': len(targets), 'raw_category_counts': counts})


def _run(command, cwd, environment, log, report=None, timeout=300):
    with log.open('wb') as output:
        process = subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=output, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise TrivyError(f'Trivy превысил лимит {timeout} секунд.')
                if log.stat().st_size > 2 * 1024 * 1024 or report and report.exists() and report.stat().st_size > MAX_REPORT:
                    raise TrivyError('Trivy превысил лимит размера отчёта.')
                time.sleep(0.1)
        except BaseException:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    if process.returncode != 0:
        raise TrivyError(f'Trivy завершился с ошибкой ({process.returncode}); проверка неполная.')
    if log.stat().st_size > 2 * 1024 * 1024:
        raise TrivyError('Trivy превысил лимит размера диагностики.')
    # DB mirrors can fail independently: exit 0 means a mirror succeeded. The caller
    # additionally validates DB metadata/freshness, and the scan must open that DB.
    if '--download-db-only' in command:
        return
    # Trivy logs the expected embedded-check fallback at ERROR level on a fresh cache.
    diagnostics = b'\n'.join(line for line in log.read_bytes().splitlines()
                             if not (b'\tERROR\t[misconfig] Falling back to embedded checks' in line
                                     and b'cache does not exist at' in line)
                             and b'\tWARN\t[pip] Unable to find python `site-packages` directory. License detection is skipped.' not in line)
    if log.stat().st_size > 2 * 1024 * 1024 or re.search(rb'\b(WARN|ERROR|FATAL)\b', diagnostics):
        raise TrivyError('Trivy сообщил о неполной проверке. Проверьте доступность базы CVE и корректность файлов.')


def log_trivy_storage():
    cache = Path.home() / ".cache" / "bultshield-trivy"
    cache.mkdir(parents=True, exist_ok=True)
    # Numeric, platform-only diagnostics: never print paths, environment or source.
    try:
        mounts = [line.split() for line in Path('/proc/mounts').read_text().splitlines()]
        matching = [entry for entry in mounts if str(cache).startswith(entry[1].rstrip('/') + '/')]
        filesystem = max(matching, key=lambda entry: len(entry[1]))[2]
        temporary_mounts = [entry for entry in mounts if gettempdir() == entry[1] or gettempdir().startswith(entry[1].rstrip('/') + '/')]
        temporary_filesystem = max(temporary_mounts, key=lambda entry: len(entry[1]))[2]
        limit_file = Path('/sys/fs/cgroup/memory.max')
        memory_limit = limit_file.read_text().strip() if limit_file.exists() else 'unavailable'
        print(f'TRIVY_STORAGE filesystem={filesystem} default_temp_filesystem={temporary_filesystem} memory_limit={memory_limit} free_bytes={shutil.disk_usage(cache).free}', flush=True)
    except (OSError, ValueError, IndexError):
        pass


def run_trivy(repository):
    repository = Path(repository).resolve()
    executable = shutil.which('trivy')
    if not executable:
        raise TrivyError('Trivy не установлен в worker.')
    try:
        _check_size(repository)
        # Worker-owned cache persists between jobs, but no repository files are stored here.
        cache = Path.home() / '.cache' / 'bultshield-trivy'
        cache.mkdir(parents=True, exist_ok=True)
        # Keep OCI downloads/unpacking off platform /tmp mounts that may use RAM.
        with TemporaryDirectory(prefix='job-', dir=cache) as temporary:
            workspace = Path(temporary)
            source = workspace / 'source'
            files = _snapshot(repository, source)
            if not files:
                return TrivyReport([], {'scanned_files': 0, 'scope': 'supported_manifests_and_configurations'})
            config, ignore = workspace / 'policy.yaml', workspace / 'ignore'
            config.write_text('{}\n')
            ignore.write_text('')
            environment = {
                'PATH': os.pathsep.join([str(Path(executable).parent), os.defpath]),
                'HOME': str(workspace), 'TMPDIR': str(workspace), 'LANG': 'C.UTF-8',
                'GOMAXPROCS': '1', 'GOMEMLIMIT': '96MiB', 'GOGC': '20',
            }
            common = [executable, 'fs', '--config', str(config), '--cache-dir', str(cache),
                      '--disable-telemetry', '--skip-version-check', '--no-progress', '--timeout', '5m']
            # Update only the trusted public vulnerability DB, without giving this step source files.
            print('TRIVY_DB_UPDATE_STARTED', flush=True)
            _run(common + ['--download-db-only'], workspace, environment, workspace / 'db.log')
            print('TRIVY_DB_UPDATE_COMPLETED', flush=True)
            metadata = json.loads((cache / 'db' / 'metadata.json').read_text())
            updated = datetime.fromisoformat(metadata['UpdatedAt'].replace('Z', '+00:00'))
            if updated.tzinfo is None or not timedelta(0) <= datetime.now(timezone.utc) - updated <= timedelta(hours=24):
                raise TrivyError('База CVE Trivy устарела или имеет некорректную дату.')
            report = workspace / 'report.json'
            command = common + [
                '--scanners', 'vuln,misconfig', '--pkg-types', 'library', '--offline-scan',
                '--skip-db-update', '--skip-java-db-update', '--skip-check-update', '--skip-vex-repo-update',
                '--misconfig-scanners', 'dockerfile,kubernetes', '--include-non-failures',
                '--ignorefile', str(ignore), '--include-dev-deps', '--list-all-pkgs=false',
                '--file-patterns', 'pip:requirements.*\\.txt$',
                '--parallel', '1', '--format', 'json', '--output', str(report), str(source),
            ]
            print('TRIVY_ANALYSIS_STARTED', flush=True)
            _run(command, workspace, environment, workspace / 'scan.log', report)
            print('TRIVY_ANALYSIS_COMPLETED', flush=True)
            if not report.is_file() or report.stat().st_size > MAX_REPORT:
                raise TrivyError('JSON Trivy отсутствует или превышает 20 МБ.')
            parsed = parse_trivy_report(json.loads(report.read_text()), files)
            parsed.summary.update(input_files=len(files), db_updated_at=metadata['UpdatedAt'],
                                  scope='supported_manifests_and_configurations', checks='embedded',
                                  version=TRIVY_VERSION)
            return parsed
    except GitleaksError as exc:
        raise TrivyError(str(exc)) from None
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        raise TrivyError('Не удалось прочитать файлы, базу CVE или отчёт Trivy.') from None

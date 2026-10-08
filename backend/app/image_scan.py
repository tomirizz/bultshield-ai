"""Сканирование Docker-образа из разрешённого реестра через Trivy.

Образ только скачивается и читается, он никогда не запускается. Любая неполная проверка
считается ошибкой, а не «чистым» результатом.
"""
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

from .image_report import ImageReport, ImageReportError, parse_image_report
from .scan_runtime import (
    inherited_lock,
    limited_command,
    temporary_directory,
    timeout_seconds,
)
from .scanner_catalog import TRIVY_VERSION

DEFAULT_PLATFORM = 'linux/amd64'
MAX_REPORT = 20 * 1024 * 1024
MAX_LOG = 2 * 1024 * 1024
# Единственное безобидное предупреждение при сканировании образа. Любое другое считается сбоем.
ALLOWED_WARNINGS = (b'Using severities from other vendors',)

_HOST = r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::\d{1,5})?'
_COMPONENT = r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*'
_TAG = r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}'
_DIGEST = r'sha256:[0-9a-f]{64}'
_REFERENCE = re.compile(
    rf'(?P<host>{_HOST})/(?P<path>{_COMPONENT}(?:/{_COMPONENT})*)(?::(?P<tag>{_TAG})|@(?P<digest>{_DIGEST}))')
_PLATFORM = re.compile(r'[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9]+)?')


class ImageScanError(RuntimeError):
    """Проверка образа не выполнена или неполна. Это не означает, что уязвимостей нет."""


@dataclass(frozen=True)
class ImageRef:
    host: str
    path: str
    tag: str | None
    digest: str | None

    @property
    def repository(self):
        return f'{self.host}/{self.path}'

    @property
    def text(self):
        return f'{self.repository}@{self.digest}' if self.digest else f'{self.repository}:{self.tag}'


@dataclass(frozen=True)
class ImageScanResult:
    reference: str
    digest: str
    platform: str
    db_updated_at: str
    report: ImageReport

    @property
    def summary(self):
        return {**self.report.summary, 'image': self.reference, 'digest': self.digest, 'platform': self.platform,
                'trivy_version': TRIVY_VERSION, 'db_updated_at': self.db_updated_at, 'scope': 'registry_image'}


def allowed_registries():
    """Реестры из настройки IMAGE_ALLOWED_REGISTRIES (через запятую). По умолчанию список пуст."""
    return {item.strip().lower() for item in os.environ.get('IMAGE_ALLOWED_REGISTRIES', '').split(',') if item.strip()}


def max_db_age_hours():
    """Предельный возраст базы CVE в часах (IMAGE_DB_MAX_AGE_HOURS, по умолчанию 48).

    Базу публикуют примерно раз в сутки, поэтому жёсткие 24 часа нарушаются каждый раз, когда
    новая сборка выходит с задержкой. Дата сборки базы всегда попадает в результат проверки.
    """
    try:
        value = int(os.environ.get('IMAGE_DB_MAX_AGE_HOURS', '48'))
    except ValueError:
        value = 0
    if not 1 <= value <= 168:
        raise ImageScanError('IMAGE_DB_MAX_AGE_HOURS должен быть целым числом от 1 до 168.')
    return value


def parse_reference(text, allowed=None):
    """Строгий разбор ссылки на образ. Реестр и тег (или digest) обязательны."""
    if not isinstance(text, str) or not 3 <= len(text) <= 255:
        raise ImageScanError('Некорректная ссылка на образ.')
    match = _REFERENCE.fullmatch(text)
    if not match:
        raise ImageScanError('Некорректная ссылка на образ. Нужен вид реестр/путь:тег или реестр/путь@sha256:digest.')
    host = match['host']
    if not (host == 'localhost' or '.' in host or ':' in host):
        raise ImageScanError('Укажите реестр явно, например ghcr.io/владелец/приложение:тег.')
    allowed = allowed_registries() if allowed is None else allowed
    if host not in allowed:
        raise ImageScanError('Реестр не входит в список разрешённых (настройка IMAGE_ALLOWED_REGISTRIES).')
    return ImageRef(host, match['path'], match['tag'], match['digest'])


def resolve_digest(ref, repo_digests):
    """Digest образа: из ссылки или из отчёта Trivy. Без него результат нельзя привязать к образу."""
    found = set()
    for item in repo_digests:
        repository, _, digest = item.partition('@')
        if repository == ref.repository and re.fullmatch(_DIGEST, digest):
            found.add(digest)
    if ref.digest:
        if found and ref.digest not in found:
            raise ImageScanError('Digest в отчёте Trivy не совпадает с запрошенным.')
        return ref.digest
    if len(found) == 1:
        return next(iter(found))
    raise ImageScanError('Не удалось определить digest образа. Результат нельзя привязать к конкретной версии образа.')


def _run(command, cwd, environment, log, report=None, timeout=300, check_log=True):
    with log.open('wb') as output:
        process = subprocess.Popen(limited_command(command, timeout), cwd=cwd, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                   start_new_session=True, pass_fds=inherited_lock())
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise ImageScanError(f'Trivy превысил лимит {int(timeout)} секунд.')
                if log.stat().st_size > MAX_LOG or (report and report.exists() and report.stat().st_size > MAX_REPORT):
                    raise ImageScanError('Trivy превысил лимит размера отчёта.')
                time.sleep(0.1)
        except BaseException:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    if process.returncode != 0:
        raise ImageScanError(f'Trivy завершился с ошибкой ({process.returncode}); проверка неполная.')
    if log.stat().st_size > MAX_LOG:
        raise ImageScanError('Trivy превысил лимит размера диагностики.')
    if not check_log:
        # При обновлении базы зеркала могут сбоить по отдельности: успех подтверждает проверка свежести базы.
        return
    lines = [line for line in log.read_bytes().splitlines() if not any(token in line for token in ALLOWED_WARNINGS)]
    if re.search(rb'\b(WARN|ERROR|FATAL)\b', b'\n'.join(lines)):
        raise ImageScanError('Trivy сообщил о неполной проверке. Проверьте доступность образа и базы CVE.')


def _scan(source_flags, target, *, platform_flags=(), list_packages=False):
    """Общая часть: свежая база CVE, затем `trivy image` с заданным источником. Возвращает (отчёт, дата базы)."""
    executable = shutil.which('trivy')
    if not executable:
        raise ImageScanError('Trivy не установлен в worker.')
    timeout = timeout_seconds('TRIVY_TIMEOUT_SECONDS', 600)
    max_age = max_db_age_hours()
    cache = Path.home() / '.cache' / 'bultshield-trivy'
    try:
        cache.mkdir(parents=True, exist_ok=True)
        with temporary_directory(prefix='image-', dir=cache) as temporary:
            workspace = Path(temporary)
            config, ignore, report = workspace / 'policy.yaml', workspace / 'ignore', workspace / 'report.json'
            # Пустые политики: ничего из внешнего окружения не влияет на правила проверки.
            config.write_text('{}\n')
            ignore.write_text('')
            environment = {
                'PATH': os.pathsep.join([str(Path(executable).parent), os.defpath]),
                'HOME': str(workspace), 'TMPDIR': str(workspace), 'LANG': 'C.UTF-8',
                'GOMAXPROCS': '1', 'GOMEMLIMIT': '32MiB', 'GOGC': '10',
            }
            deadline = time.monotonic() + timeout
            flags = ['--config', str(config), '--cache-dir', str(cache), '--disable-telemetry',
                     '--skip-version-check', '--no-progress', '--timeout', f'{timeout}s']
            _run([executable, 'fs', *flags, '--download-db-only'], workspace, environment, workspace / 'db.log',
                 timeout=max(0, deadline - time.monotonic()), check_log=False)
            metadata = json.loads((cache / 'db' / 'metadata.json').read_text())
            updated = datetime.fromisoformat(metadata['UpdatedAt'].replace('Z', '+00:00'))
            if updated.tzinfo is None or not timedelta(0) <= datetime.now(timezone.utc) - updated <= timedelta(hours=max_age):
                raise ImageScanError('База CVE Trivy устарела или имеет некорректную дату.')
            command = [executable, 'image', *flags, *source_flags, *platform_flags,
                       *(['--list-all-pkgs'] if list_packages else []),
                       '--scanners', 'vuln', '--skip-db-update', '--skip-java-db-update', '--skip-check-update',
                       '--skip-vex-repo-update', '--ignorefile', str(ignore), '--format', 'json',
                       '--output', str(report), *target]
            _run(command, workspace, environment, workspace / 'image.log', report,
                 timeout=max(0, deadline - time.monotonic()))
            if not report.is_file() or report.stat().st_size > MAX_REPORT:
                raise ImageScanError('JSON Trivy отсутствует или превышает 20 МБ.')
            parsed = parse_image_report(json.loads(report.read_text()), collect_packages=list_packages)
            return parsed, metadata['UpdatedAt']
    except ImageReportError as exc:
        raise ImageScanError(str(exc)) from None
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        raise ImageScanError('Не удалось прочитать файлы, базу CVE или отчёт Trivy.') from None


def run_image_scan(reference, *, platform=None):
    ref = parse_reference(reference)
    platform = platform or os.environ.get('IMAGE_SCAN_PLATFORM') or DEFAULT_PLATFORM
    if not _PLATFORM.fullmatch(platform):
        raise ImageScanError('Некорректная платформа образа.')
    # Список пакетов нужен, чтобы после исправления отличить «находка исчезла» от «Trivy не увидел приложение».
    parsed, updated = _scan(['--image-src', 'remote'], [ref.text], platform_flags=['--platform', platform], list_packages=True)
    digest = resolve_digest(ref, parsed.summary['repo_digests'])
    return ImageScanResult(ref.text, digest, platform, updated, parsed)


MAX_ARCHIVE = 2 * 1024 ** 3


@dataclass(frozen=True)
class ArchiveScanResult:
    """Результат сканирования локального образа из `docker save`. У такого образа нет digest реестра."""
    archive: str
    db_updated_at: str
    report: ImageReport


def run_archive_scan(archive):
    """Скан образа из tar-архива (`docker save`). Образ не запускается и не загружается в реестр."""
    path = Path(archive) if isinstance(archive, (str, os.PathLike)) else None
    if path is None or not path.is_absolute() or path.suffix != '.tar' or not path.is_file():
        raise ImageScanError('Архив образа не найден или имеет неподдерживаемый вид.')
    if not 0 < path.stat().st_size <= MAX_ARCHIVE:
        raise ImageScanError('Архив образа пуст или превышает лимит 2 ГБ.')
    parsed, updated = _scan([], ['--input', str(path)], list_packages=True)
    return ArchiveScanResult(str(path), updated, parsed)

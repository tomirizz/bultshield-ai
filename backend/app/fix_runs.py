"""Запуск агента исправлений для проверки образа и сохранение результата в БД.

Что делает: берёт находки образа из БД, запускает агента (fix_agent) на копии проекта и записывает результат
в dependency_fix_runs вместе с digest образа и коммитом проекта, к которым он относится.
Чего не делает: не меняет проект и не создаёт PR. Результат относится к проверке в песочнице: он никогда
не означает, что работающее приложение исправлено.
Сбой агента или сканера сохраняется как FAILED и никогда не превращается в «исправлено» или «уязвимостей нет».
"""
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from .fix_agent import run_fix_agent
from .models import DependencyFixRun, Finding, Scan, ScanStatus

# Запуск, который «идёт» дольше этого срока, считается прерванным (процесс мог умереть, не записав итог).
STALE_AFTER = timedelta(hours=2)
MAX_DIFF = 100_000
MAX_LOG = 4_000
MAX_MESSAGE = 300
COMMIT = re.compile(r'[0-9a-f]{40}')
PR_URL = re.compile(r'https://github\.com/(?P<repo>[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100})/pull/(?P<number>[1-9]\d{0,8})')


class FixRunError(RuntimeError):
    """Запуск нельзя начать или результат нельзя сохранить. Текст безопасен для показа пользователю."""


def now():
    return datetime.now(UTC)


def effective_status(run, current=None):
    """Статус запуска с учётом прерванных: зависший RUNNING показывается как FAILED."""
    if run.status == 'RUNNING' and (current or now()) - (run.started_at or run.created_at) > STALE_AFTER:
        return 'FAILED'
    return run.status


def findings_for_agent(rows):
    """Находки образа из БД в виде, который принимает агент (как после parse_image_report)."""
    result = []
    for row in rows:
        extra = row.extra or {}
        result.append({
            'category': 'dependency', 'source': 'image', 'origin': extra.get('origin'), 'file': row.file,
            'rule_id': row.rule_id, 'severity': row.original_severity or row.severity.value.upper(),
            'ecosystem': extra.get('ecosystem'), 'package': extra.get('package'),
            'installed_version': extra.get('installed_version'), 'fixed_version': extra.get('fixed_version'),
            'package_id': extra.get('package_id'), 'cve': row.cve, 'fix_status': extra.get('fix_status'),
            'manual_reason': extra.get('manual_reason'),
        })
    return result


def detect_commit(project_dir):
    """Коммит проекта, на котором проверялись обновления. None, если это не git-репозиторий."""
    root = Path(project_dir)
    if not (root / '.git').exists():
        return None

    def git(*args):
        try:
            done = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            raise FixRunError('Не удалось выполнить git в каталоге проекта: версию кода определить нельзя.') from None
        if done.returncode != 0:
            raise FixRunError('Не удалось определить коммит проекта: версию кода определить нельзя.')
        return done.stdout.strip()

    if git('status', '--porcelain'):
        raise FixRunError('В проекте есть незакоммиченные изменения: результат нельзя привязать к коммиту. '
                          'Закоммитьте или отмените изменения.')
    sha = git('rev-parse', 'HEAD')
    if not COMMIT.fullmatch(sha):
        raise FixRunError('Git вернул неожиданный идентификатор коммита.')
    return sha


def _load_scan(db, scan_id):
    scan = db.scalar(select(Scan).where(Scan.id == scan_id).with_for_update())
    if scan is None:
        raise FixRunError('Проверка не найдена.')
    if scan.kind != 'image':
        raise FixRunError('Агент исправлений работает только с проверками образа.')
    if scan.status != ScanStatus.COMPLETED or ((scan.scanner_results or {}).get('trivy') or {}).get('status') != 'COMPLETED':
        raise FixRunError('Проверка образа не завершилась успешно: результат не определён, исправления не предлагаются.')
    return scan


def create_run(db, scan_id, commit_sha=None):
    """Создаёт запуск в статусе RUNNING и сразу сохраняет его, чтобы отчёт показал «идёт проверка»."""
    scan = _load_scan(db, scan_id)
    if commit_sha is not None and not COMMIT.fullmatch(commit_sha):
        raise FixRunError('Коммит должен быть полным SHA-1 (40 символов, нижний регистр).')
    current = now()
    for run in db.scalars(select(DependencyFixRun).where(DependencyFixRun.scan_id == scan.id, DependencyFixRun.status == 'RUNNING')):
        if effective_status(run, current) == 'RUNNING':
            raise FixRunError('Для этой проверки исправления уже проверяются. Дождитесь результата.')
        run.status, run.completed_at = 'FAILED', current
        run.error_message = 'Запуск прерван: итог не был записан.'
    run = DependencyFixRun(project_id=scan.project_id, scan_id=scan.id, status='RUNNING', started_at=current, commit_sha=commit_sha,
                           image_digest=((scan.scanner_results or {}).get('trivy') or {}).get('digest'))
    db.add(run)
    db.commit()
    return run


def _clip(text, limit):
    if isinstance(text, str) and len(text) > limit:
        return text[:limit] + '\n[обрезано]'
    return text


def _trim(verification):
    """Результат проверки без лишнего объёма: диффы и логи шагов ограничены."""
    if not isinstance(verification, dict):
        return verification
    data = dict(verification)
    data['diff'] = _clip(data.get('diff'), MAX_DIFF)
    data['steps'] = [{**step, 'log_tail': _clip(step.get('log_tail'), MAX_LOG)} for step in data.get('steps') or []]
    return data


def complete_run(db, run_id, result, rows):
    """Записывает результат агента. rows: находки образа этой проверки (чтобы связать пакеты с находками)."""
    run = db.scalar(select(DependencyFixRun).where(DependencyFixRun.id == run_id).with_for_update())
    if run is None or run.status != 'RUNNING':
        raise FixRunError('Запуск уже завершён или не найден.')
    data = result.as_dict()
    items = []
    for item in data['packages']:
        rule_ids = list(item.pop('finding_ids'))   # у агента это идентификаторы уязвимостей (CVE), не записи БД
        linked = [str(r.id) for r in rows if (r.extra or {}).get('origin') == 'app' and (r.extra or {}).get('package') == item['package']
                  and r.rule_id in rule_ids]
        items.append({**item, 'rule_ids': rule_ids, 'finding_ids': linked, 'verification': _trim(item.get('verification'))})
    run.items, run.other, run.summary = items, data['other'], data['summary']
    run.combined = _trim(data['combined'])
    run.status, run.completed_at, run.error_message = 'COMPLETED', now(), None
    db.commit()
    return run


def fail_run(db, run_id, message):
    run = db.scalar(select(DependencyFixRun).where(DependencyFixRun.id == run_id).with_for_update())
    if run is not None and run.status == 'RUNNING':
        run.status, run.completed_at = 'FAILED', now()
        run.error_message = (message or 'Запуск завершился ошибкой.')[:MAX_MESSAGE]
        db.commit()
    return run


def execute_run(db, scan_id, project_dir, *, commit_sha=None, agent=run_fix_agent, **agent_kwargs):
    """Полный запуск: создать запись, проверить обновления в песочнице, сохранить итог. Возвращает (запуск, результат агента).

    Результат агента (с файлами для PR) остаётся только в памяти этого процесса: в БД файлы не пишутся.
    Всё, что не удалось, остаётся FAILED с понятной причиной. Находки при этом сохраняют статус «обнаружена».
    """
    if commit_sha is None:
        commit_sha = detect_commit(project_dir)
    run = create_run(db, scan_id, commit_sha)
    run_id = run.id
    try:
        rows = db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)).all()
        result = agent(Path(project_dir), findings_for_agent(rows), **agent_kwargs)
        return complete_run(db, run_id, result, rows), result
    except FixRunError as exc:
        db.rollback()
        fail_run(db, run_id, str(exc))
        raise
    except Exception:
        # Подробности (пути, вывод команд) в БД и в ответ не попадают: только общая причина.
        db.rollback()
        fail_run(db, run_id, 'Агент исправлений завершился с ошибкой. Проверка обновлений не выполнена.')
        raise FixRunError('Агент исправлений завершился с ошибкой. Проверка обновлений не выполнена.') from None


def run_agent_for_scan(db, scan_id, project_dir, **kwargs):
    return execute_run(db, scan_id, project_dir, **kwargs)[0]


def record_pull_request(db, run_id, *, url, branch, base_sha, created):
    """Сохраняет данные PR, созданного по результатам этого запуска. Слияние здесь не отражается: его проверяет confirm_deployment."""
    match = PR_URL.fullmatch(url) if isinstance(url, str) else None
    if match is None:
        raise FixRunError('Некорректная ссылка на PR.')
    run = db.scalar(select(DependencyFixRun).where(DependencyFixRun.id == run_id).with_for_update())
    if run is None or run.status != 'COMPLETED':
        raise FixRunError('PR можно привязать только к завершённому запуску.')
    run.pull_request = {'url': url, 'repo': match['repo'], 'number': int(match['number']), 'branch': branch, 'base_sha': base_sha,
                        'created': bool(created), 'recorded_at': now().isoformat(), 'merged': False}
    run.deployment = None   # результат прежней проверки относился к другому PR
    db.commit()
    return run


def latest_runs(db, scan_id):
    """Последний запуск, последний завершённый и последний, для которого проверялось применение (могут совпадать или быть None)."""
    ordering = (DependencyFixRun.created_at.desc(), DependencyFixRun.id.desc())
    latest = db.scalar(select(DependencyFixRun).where(DependencyFixRun.scan_id == scan_id).order_by(*ordering).limit(1))
    completed = db.scalar(select(DependencyFixRun).where(DependencyFixRun.scan_id == scan_id, DependencyFixRun.status == 'COMPLETED')
                          .order_by(*ordering).limit(1))
    evaluated = db.scalar(select(DependencyFixRun).where(DependencyFixRun.scan_id == scan_id, DependencyFixRun.deployment.is_not(None))
                          .order_by(*ordering).limit(1))
    return {'latest': latest, 'completed': completed, 'evaluated': evaluated}

"""Пояснения языковой модели как фоновое задание: запрос возвращается сразу, работу выполняет worker.

Почему в фоне: ответ модели может идти десятки секунд, а на проверку приходится много запросов. Пока задание идёт,
статус и результат хранятся в БД, поэтому их можно прочитать позже. Недоступность модели не ломает проверку: задание
завершается, а причина видна в разделе llm отчёта. Пояснения — предположения и статусы находок не меняют.
"""
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_engine
from .llm import LLMNotConfigured, build_provider
from .models import LLMJob, ScanStatus

ACTIVE = ('QUEUED', 'RUNNING')
QUEUE_LIMIT = 10
STALE = timedelta(minutes=15)
MAX_ERRORS = 10


def now():
    return datetime.now(timezone.utc)


def job_out(job):
    if job is None:
        return None
    return {'id': str(job.id), 'check_id': str(job.scan_id), 'status': job.status, 'created_at': job.created_at,
            'started_at': job.started_at, 'completed_at': job.completed_at, 'result': job.summary, 'error': job.error_message}


def latest_job(db, scan_id):
    return db.scalar(select(LLMJob).where(LLMJob.scan_id == scan_id).order_by(LLMJob.created_at.desc(), LLMJob.id.desc()).limit(1))


def enqueue(db, scan):
    """Ставит задание в очередь. Если для проверки задание уже идёт, возвращает его (created=False)."""
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(409, 'Проверка ещё не завершена или завершилась ошибкой: пояснять пока нечего.')
    try:
        build_provider(get_settings())
    except LLMNotConfigured as exc:
        # Честный отказ вместо задания, которое молча ничего не сделает.
        raise HTTPException(409, f'Модель не подключена: {exc}') from None
    active = db.scalar(select(LLMJob).where(LLMJob.scan_id == scan.id, LLMJob.status.in_(ACTIVE)))
    if active is not None:
        return active, False
    pending = db.scalar(select(func.count()).select_from(LLMJob).where(LLMJob.status.in_(ACTIVE))) or 0
    if pending >= QUEUE_LIMIT:
        raise HTTPException(429, 'Очередь пояснений заполнена. Повторите запрос позже.')
    job = LLMJob(project_id=scan.project_id, scan_id=scan.id, status='QUEUED')
    db.add(job)
    try:
        db.commit()
    except IntegrityError:
        # Два одинаковых запроса пришли одновременно: второй получает задание первого.
        db.rollback()
        active = db.scalar(select(LLMJob).where(LLMJob.scan_id == scan.id, LLMJob.status.in_(ACTIVE)))
        if active is None:
            raise
        return active, False
    return job, True


def _short(summary):
    summary = dict(summary)
    summary['errors'] = [str(e)[:300] for e in (summary.get('errors') or [])[:MAX_ERRORS]]
    summary.pop('prompts', None)
    return summary


def process_next():
    """Берёт одно задание из очереди и выполняет его. True, если задание было."""
    with Session(get_engine()) as db:
        db.execute(update(LLMJob).where(LLMJob.status == 'RUNNING', LLMJob.started_at < now() - STALE).values(
            status='FAILED', completed_at=now(), error_message='Время обработки истекло. Запросите пояснения заново: уже полученные сохранены.'))
        job = db.scalar(select(LLMJob).where(LLMJob.status == 'QUEUED').order_by(LLMJob.created_at).limit(1).with_for_update(skip_locked=True))
        if job is None:
            db.commit()
            return False
        job.status, job.started_at = 'RUNNING', now()
        job_id, scan_id = job.id, job.scan_id
        db.commit()
    from .llm_explain import explain_check  # здесь, чтобы модуль можно было импортировать из check_report без цикла
    with Session(get_engine(), expire_on_commit=False) as db:
        try:
            summary = _short(explain_check(db, scan_id))
            outcome = dict(status='COMPLETED', summary=summary, error_message=None)
        except LookupError:
            outcome = dict(status='FAILED', summary=None, error_message='Проверка не найдена.')
        except Exception:
            db.rollback()
            outcome = dict(status='FAILED', summary=None, error_message='Внутренняя ошибка. Запросите пояснения заново.')
        db.execute(update(LLMJob).where(LLMJob.id == job_id).values(completed_at=now(), **outcome))
        db.commit()
    return True

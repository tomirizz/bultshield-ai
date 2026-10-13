"""API запуска проверок: на входе репозиторий, коммит или образ, на выходе идентификатор задания, статус и отчёт."""
import re
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .api import queue_source_scan
from .check_report import load_report
from .database import get_session
from .image_jobs import create_image_scan
from .llm_jobs import enqueue, job_out, latest_job
from .llm_report import llm_section
from .models import LLMCall, Scan
from .schemas import ScanOut

router = APIRouter(prefix='/api')
DB = Annotated[Session, Depends(get_session)]


COMMIT = re.compile(r'[0-9a-f]{40}')


@router.get('/checks-configuration')
def checks_configuration():
    """Public-to-the-owner settings only; never credentials or internal endpoints."""
    from .config import get_settings
    from .image_scan import allowed_registries
    settings = get_settings()
    return {'image_registries': sorted(allowed_registries()), 'rescan_hours': settings.image_rescan_hours,
            'llm_provider': settings.llm_provider,
            'sandbox_available_in_web': False,
            'sandbox_note': 'Проверка обновлений в песочнице пока не подключена к веб-интерфейсу. Исправление нельзя считать проверенным до сборки, тестов, запуска и повторного сканирования.',
            'runtime_deployment_observed': False}


class CheckRequest(BaseModel):
    # Неизвестные поля отклоняются: нельзя молча игнорировать то, что не поддерживается.
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    repository_id: uuid.UUID
    image: str | None = Field(default=None, max_length=255)
    commit: str | None = Field(default=None, max_length=64)
    # watch: образ опубликован, его нужно перепроверять по расписанию. trigger: только пометка в отчёте, на права не влияет.
    watch: bool = False
    trigger: Literal['api', 'ci'] = 'api'

    @field_validator('commit')
    @classmethod
    def full_commit(cls, value):
        # Только полный SHA-1: сокращённый или ветку нельзя однозначно привязать к версии кода.
        if value is not None and not COMMIT.fullmatch(value):
            raise ValueError('Коммит должен быть полным SHA-1: 40 символов 0-9 и a-f в нижнем регистре.')
        return value


@router.post('/checks', response_model=ScanOut, status_code=202)
def create_check(data: CheckRequest, db: DB):
    """Что проверять, определяет вход.

    Только repository_id: исходники репозитория (конец ветки по умолчанию).
    repository_id и commit: исходники именно этого коммита.
    repository_id и image: образ из разрешённого реестра.
    """
    if data.image is not None and data.commit is not None:
        raise HTTPException(422, 'Укажите либо image, либо commit: образ и коммит проверяются отдельно.')
    if data.watch and data.image is None:
        raise HTTPException(422, 'watch нужен только для образа: за исходниками следит непрерывная проверка репозитория.')
    if data.image is not None:
        return create_image_scan(db, data.repository_id, data.image, watch=data.watch, trigger=data.trigger)
    return queue_source_scan(data.repository_id, db, data.commit, data.trigger)


@router.get('/checks/{check_id}', response_model=ScanOut)
def get_check(check_id: uuid.UUID, db: DB):
    scan = db.get(Scan, check_id)
    # Служебные проверки исправлений не считаются проверками пользователя.
    if scan is None or scan.kind == 'verification':
        raise HTTPException(404, 'Проверка не найдена.')
    return scan


@router.get('/checks/{check_id}/report')
def get_check_report(check_id: uuid.UUID, db: DB, limit: Annotated[int, Query(ge=1, le=500)] = 100,
                     offset: Annotated[int, Query(ge=0)] = 0):
    """Отчёт: факты (что измерили сканеры), предположения (AI) и предложенные действия раздельно."""
    return load_report(db, get_check(check_id, db), limit, offset)


@router.post('/checks/{check_id}/explanations', status_code=202)
def request_explanations(check_id: uuid.UUID, db: DB):
    """Запросить у модели пояснения к находкам завершённой проверки. Работа идёт в фоне; повторный запрос не создаёт дубликат."""
    job, created = enqueue(db, get_check(check_id, db))
    return {**job_out(job), 'already_running': not created}


@router.get('/checks/{check_id}/explanations')
def get_explanations(check_id: uuid.UUID, db: DB):
    """Состояние последнего задания на пояснения и сводка по запросам к модели. Сами пояснения лежат в отчёте проверки."""
    scan = get_check(check_id, db)
    calls = db.scalars(select(LLMCall).where(LLMCall.scan_id == scan.id).order_by(LLMCall.created_at.desc(), LLMCall.id.desc())).all()
    job = latest_job(db, scan.id)
    return {'job': job_out(job), 'llm': llm_section(calls, job)}

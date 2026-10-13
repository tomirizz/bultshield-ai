"""API запуска проверок: на входе репозиторий, коммит или образ, на выходе идентификатор задания, статус и отчёт."""
import re
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from .api import queue_source_scan
from .check_report import load_report
from .database import get_session
from .image_jobs import create_image_scan
from .models import Scan
from .schemas import ScanOut

router = APIRouter(prefix='/api')
DB = Annotated[Session, Depends(get_session)]


COMMIT = re.compile(r'[0-9a-f]{40}')


class CheckRequest(BaseModel):
    # Неизвестные поля отклоняются: нельзя молча игнорировать то, что не поддерживается.
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    repository_id: uuid.UUID
    image: str | None = Field(default=None, max_length=255)
    commit: str | None = Field(default=None, max_length=64)

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
    if data.image is not None:
        return create_image_scan(db, data.repository_id, data.image)
    return queue_source_scan(data.repository_id, db, data.commit)


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

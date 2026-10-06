"""API запуска проверок: на входе репозиторий (и образ), на выходе идентификатор задания, статус и отчёт."""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .api import create_scan
from .check_report import load_report
from .database import get_session
from .image_jobs import create_image_scan
from .models import Scan
from .schemas import ScanOut, ScanRequest

router = APIRouter(prefix='/api')
DB = Annotated[Session, Depends(get_session)]


class CheckRequest(BaseModel):
    # Неизвестные поля (например, commit) отклоняются: нельзя молча игнорировать то, что не поддерживается.
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    repository_id: uuid.UUID
    image: str | None = Field(default=None, max_length=255)


@router.post('/checks', response_model=ScanOut, status_code=202)
def create_check(data: CheckRequest, db: DB):
    """Без image: проверка исходников репозитория. С image: проверка образа из разрешённого реестра."""
    if data.image is not None:
        return create_image_scan(db, data.repository_id, data.image)
    return create_scan(ScanRequest(repository_id=data.repository_id), db)


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

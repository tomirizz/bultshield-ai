"""API запуска проверок: на входе репозиторий (и образ), на выходе идентификатор задания и статус."""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .api import create_scan
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

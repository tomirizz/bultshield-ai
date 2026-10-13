"""Перепроверка опубликованных образов по расписанию.

Образ, проверенный с пометкой watch (обычно из CI), worker перепроверяет раз в IMAGE_RESCAN_HOURS: за это время в базе уязвимостей
могли появиться новые записи о пакетах, которые уже в образе. Решает последняя проверка этого образа: если она без watch,
слежение прекращено. Перепроверка встаёт в обычную очередь и подчиняется её лимитам; сбой сканера остаётся FAILED,
а не «чисто», и перепроверяется в следующий срок.
"""
import json
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_engine
from .image_jobs import create_image_scan
from .models import Scan, ScanStatus

LOCK = 820087
FINISHED = (ScanStatus.COMPLETED, ScanStatus.FAILED)


def watched_images(db):
    """Последняя проверка каждого образа (репозиторий + ссылка), если она с пометкой watch и закончилась."""
    reference = Scan.scanner_config['image']['reference'].astext
    latest = db.scalars(select(Scan).where(Scan.kind == 'image').distinct(Scan.repository_id, reference)
                        .order_by(Scan.repository_id, reference, Scan.created_at.desc(), Scan.id.desc())).all()
    return [s for s in latest if s.scanner_config.get('watch') is True and s.status in FINISHED]


def rescan_due(db, older_than, *, limit=1, now=None):
    """Ставит в очередь перепроверки образов, последняя проверка которых старше older_than. Возвращает созданные проверки."""
    now = now or datetime.now(UTC)
    due = [s for s in watched_images(db) if (s.completed_at or s.created_at) <= now - older_than]
    due.sort(key=lambda s: (s.completed_at or s.created_at, s.id))
    created = []
    for scan in due:
        if len(created) >= limit:
            break
        try:
            created.append(create_image_scan(db, scan.repository_id, scan.scanner_config['image']['reference'],
                                             watch=True, trigger='schedule', rescan_of=scan.id))
        except HTTPException as exc:
            if exc.status_code == 429:
                break  # очередь заполнена: продолжим в следующий раз
            db.rollback()  # образ больше нельзя проверять (например, реестр убрали из разрешённых): пропускаем, не падаем
    return created


def poll_once():
    """Вызывается worker. Один процесс за раз (блокировка), не больше одной перепроверки за вызов.

    Возвращает описания поставленных перепроверок: [{'scan_id', 'rescan_of', 'image'}].
    """
    hours = get_settings().image_rescan_hours
    if hours <= 0:
        return []
    engine = get_engine()
    # Блокировка держится на отдельном соединении, пока идёт работа, и снимается на нём же: так она не «залипает» в пуле соединений.
    with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as lock:
        if not lock.scalar(text('SELECT pg_try_advisory_lock(:key)'), {'key': LOCK}):
            return []
        try:
            with Session(engine, expire_on_commit=False) as db:
                created = [{'scan_id': str(scan.id), 'rescan_of': scan.scanner_config.get('rescan_of'),
                            'image': scan.scanner_config['image']['reference']} for scan in rescan_due(db, timedelta(hours=hours))]
        finally:
            lock.scalar(text('SELECT pg_advisory_unlock(:key)'), {'key': LOCK})
    for item in created:
        print(json.dumps({'event': 'image_rescan_queued', **item}), flush=True)
    return created

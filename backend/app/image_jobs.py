"""Создание задания проверки образа. Правила очереди такие же, как у обычного скана."""
from fastapi import HTTPException
from sqlalchemy import func, select

from .api import WORKSPACE_USER_ID
from .image_scan import ImageScanError, parse_reference
from .models import Repository, Scan, ScanJob, ScanStatus, User
from .scanner_catalog import TRIVY_VERSION

ACTIVE = ('QUEUED', 'RUNNING')
QUEUE_LIMIT = 10


def create_image_scan(db, repository_id, reference, *, watch=False, trigger='api', rescan_of=None):
    """Ставит проверку образа в очередь. Повторный запрос того же образа возвращает уже идущую проверку.

    watch: образ опубликован, worker будет перепроверять его по расписанию (решает последняя проверка этого образа).
    trigger: что запустило проверку: api (по запросу), ci (после сборки) или schedule (перепроверка по расписанию).
    """
    try:
        ref = parse_reference(reference)
    except ImageScanError as exc:
        raise HTTPException(422, str(exc)) from None
    # Постановку заданий сериализуем так же, как в create_scan, включая лимит очереди.
    db.scalar(select(User).where(User.id == WORKSPACE_USER_ID).with_for_update())
    repository = db.scalar(select(Repository).where(Repository.id == repository_id).with_for_update())
    if repository is None:
        raise HTTPException(404, 'Репозиторий не найден.')
    running = db.scalars(select(Scan).join(ScanJob, ScanJob.scan_id == Scan.id).where(
        Scan.repository_id == repository.id, Scan.kind == 'image', ScanJob.status.in_(ACTIVE))).all()
    for scan in running:
        if (scan.scanner_config.get('image') or {}).get('reference') == ref.text:
            if bool(scan.scanner_config.get('watch')) != watch:
                scan.scanner_config = {**scan.scanner_config, 'watch': watch}
                db.commit()
            return scan
    pending = db.scalar(select(func.count()).select_from(ScanJob).where(ScanJob.status.in_(ACTIVE))) or 0
    if pending >= QUEUE_LIMIT:
        raise HTTPException(429, 'Очередь заполнена. Дождитесь завершения текущих проверок.')
    scan = Scan(project_id=repository.project_id, repository_id=repository.id, kind='image',
                status=ScanStatus.QUEUED, target_url=ref.repository,
                scanner_config={'scanners': ['trivy'], 'scope': 'registry_image', 'branch': repository.default_branch,
                                'image': {'reference': ref.text, 'repository': ref.repository},
                                'trivy_version': TRIVY_VERSION, 'watch': watch, 'trigger': trigger,
                                **({'rescan_of': str(rescan_of)} if rescan_of else {})})
    db.add(scan)
    db.flush()
    db.add(ScanJob(scan_id=scan.id, status='QUEUED'))
    db.commit()
    db.refresh(scan)
    return scan

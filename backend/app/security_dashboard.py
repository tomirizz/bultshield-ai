"""Read-only dashboard queries. Summary and findings share the same snapshot scope."""
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .database import get_session
from .models import Category, Finding, FindingStatus, Project, Repository, Scan, Scanner, ScanStatus, Severity
from .schemas import FindingOut, ScanOut

router = APIRouter(prefix='/api')
DB = Annotated[Session, Depends(get_session)]


def check_project(db, project_id):
    if project_id is not None and db.get(Project, project_id) is None:
        raise HTTPException(404, 'Проект не найден')


def latest_scans(project_id=None, completed_only=False):
    query = select(Scan.id, Scan.repository_id, Scan.status, func.row_number().over(
        partition_by=Scan.repository_id, order_by=(Scan.created_at.desc(), Scan.id.desc())).label('position'))
    if project_id:
        query = query.where(Scan.project_id == project_id)
    if completed_only:
        query = query.where(Scan.status == ScanStatus.COMPLETED)
    ranked = query.subquery()
    return select(ranked.c.id).where(ranked.c.position == 1)


@router.get('/security-summary')
def security_summary(db: DB, project_id: uuid.UUID | None = None):
    check_project(db, project_id)
    selected = latest_scans(project_id, completed_only=True)
    severity = {item.value: 0 for item in Severity}
    scanners = {name: 0 for name in ('gitleaks', 'semgrep', 'trivy')}
    rows = db.execute(select(Finding.severity, Finding.scanner, func.count()).where(
        Finding.scan_id.in_(selected)).group_by(Finding.severity, Finding.scanner))
    for level, scanner, count in rows:
        severity[level.value] += count
        scanners[scanner.value] = scanners.get(scanner.value, 0) + count
    repositories = select(func.count()).select_from(Repository)
    history = select(func.count()).select_from(Scan)
    if project_id:
        repositories = repositories.where(Repository.project_id == project_id)
        history = history.where(Scan.project_id == project_id)
    snapshots = db.scalars(select(Scan).where(Scan.id.in_(selected)).order_by(Scan.created_at.desc(), Scan.id)).all()
    recent = db.scalars(select(Scan).where(Scan.id.in_(latest_scans(project_id))).order_by(Scan.created_at.desc(), Scan.id)).all()
    return {'scope': 'latest', 'total': sum(severity.values()), 'severity': severity, 'scanners': scanners,
            'repository_count': db.scalar(repositories), 'scanned_repositories': len(snapshots),
            'scan_count': db.scalar(history), 'snapshots': [ScanOut.model_validate(s) for s in snapshots],
            'latest_runs': [ScanOut.model_validate(s) for s in recent]}


@router.get('/findings-page')
def findings_page(
    db: DB, project_id: uuid.UUID | None = None, scan_id: uuid.UUID | None = None,
    severity: Severity | None = None, scanner: Scanner | None = None,
    category: Category | None = None, status: FindingStatus | None = None,
    q: Annotated[str, Query(max_length=200)] = '',
    scope: Literal['latest', 'all'] = 'latest',
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    check_project(db, project_id)
    query = select(Finding)
    if project_id:
        query = query.where(Finding.project_id == project_id)
    if scan_id:
        scan = db.get(Scan, scan_id)
        if scan is None or project_id and scan.project_id != project_id:
            raise HTTPException(404, 'Проверка не найдена в выбранном проекте')
        query = query.where(Finding.scan_id == scan_id)
    elif scope == 'latest':
        query = query.where(Finding.scan_id.in_(latest_scans(project_id, completed_only=True)))
    for field, value in [(Finding.severity, severity), (Finding.scanner, scanner),
                         (Finding.category, category), (Finding.status, status)]:
        if value is not None:
            query = query.where(field == value)
    if q.strip():
        term = '%' + q.strip().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        query = query.where(or_(*(field.ilike(term, escape='\\') for field in (
            Finding.title, Finding.description, Finding.file, Finding.rule_id, Finding.cve, Finding.cwe,
            Finding.extra['package'].astext))))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    items = db.scalars(query.order_by(Finding.created_at.desc(), Finding.id).offset(offset).limit(limit)).all()
    return {'total': total, 'limit': limit, 'offset': offset, 'items': [FindingOut.model_validate(item) for item in items]}

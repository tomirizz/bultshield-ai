import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_session
from .models import AIAnalysis, Category, Finding, FindingStatus, Fix, Project, Repository, Rescan, Scan, ScanJob, Scanner, ScanStatus, Severity, User
from .scanner_catalog import scan_configuration
from .schemas import (
    AIAnalysisOut,
    FindingOut,
    FixOut,
    ProjectCreate,
    ProjectOut,
    RepositoryCreate,
    RepositoryOut,
    RescanOut,
    RescanRequest,
    ScanOut,
    ScanRequest,
)

router = APIRouter(prefix="/api")
DB = Annotated[Session, Depends(get_session)]
Limit = Annotated[int, Query(ge=1, le=100)]
WORKSPACE_USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")


def require_project(db: Session, project_id: uuid.UUID) -> Project:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Проект не найден")
    return project


def project_out(db: Session, project: Project) -> ProjectOut:
    item = ProjectOut.model_validate(project)
    item.repositories = [
        RepositoryOut.model_validate(r) for r in db.scalars(select(Repository).where(Repository.project_id == project.id).order_by(Repository.created_at))
    ]
    item.scan_count = db.scalar(select(func.count()).select_from(Scan).where(Scan.project_id == project.id)) or 0
    item.finding_count = db.scalar(select(func.count()).select_from(Finding).where(Finding.project_id == project.id)) or 0
    return item


@router.get("/overview")
def overview(db: DB):
    counts = {
        name: db.scalar(select(func.count()).select_from(model))
        for name, model in [("projects", Project), ("repositories", Repository), ("scans", Scan), ("findings", Finding)]
    }
    return {**counts, "stage": 9, "capabilities": {"scanners": True, "ai": get_settings().ai_enabled, "rescans": False}}


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(db: DB, limit: Limit = 100, offset: Annotated[int, Query(ge=0)] = 0):
    projects = db.scalars(select(Project).order_by(Project.created_at.desc(), Project.id).offset(offset).limit(limit))
    return [project_out(db, project) for project in projects]


@router.post("/projects", response_model=ProjectOut, status_code=201)
def create_project(data: ProjectCreate, db: DB):
    try:
        db.execute(insert(User).values(id=WORKSPACE_USER_ID, display_name="MVP workspace").on_conflict_do_nothing(index_elements=["id"]))
        project = Project(owner_id=WORKSPACE_USER_ID, name=data.name, description=data.description, target_url=data.target_url)
        db.add(project)
        db.flush()
        if data.repository:
            db.add(Repository(project_id=project.id, **data.repository.model_dump()))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Проект с таким названием уже существует") from None
    db.refresh(project)
    return project_out(db, project)


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: uuid.UUID, db: DB):
    return project_out(db, require_project(db, project_id))


@router.get("/projects/{project_id}/repositories", response_model=list[RepositoryOut])
def list_repositories(project_id: uuid.UUID, db: DB):
    require_project(db, project_id)
    return db.scalars(select(Repository).where(Repository.project_id == project_id).order_by(Repository.created_at)).all()


@router.post("/projects/{project_id}/repositories", response_model=RepositoryOut, status_code=201)
def add_repository(project_id: uuid.UUID, data: RepositoryCreate, db: DB):
    require_project(db, project_id)
    repository = Repository(project_id=project_id, **data.model_dump())
    db.add(repository)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Этот репозиторий уже добавлен в проект") from None
    db.refresh(repository)
    return repository


@router.get("/scans", response_model=list[ScanOut])
def list_scans(db: DB, project_id: uuid.UUID | None = None, limit: Limit = 100, offset: Annotated[int, Query(ge=0)] = 0):
    query = select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc()).offset(offset).limit(limit)
    if project_id:
        require_project(db, project_id)
        query = query.where(Scan.project_id == project_id)
    return db.scalars(query).all()


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    db: DB,
    project_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    severity: Severity | None = None,
    scanner: Scanner | None = None,
    category: Category | None = None,
    status: FindingStatus | None = None,
    limit: Limit = 100,
):
    query = select(Finding).order_by(Finding.created_at.desc(), Finding.id).limit(limit)
    if project_id:
        require_project(db, project_id)
        query = query.where(Finding.project_id == project_id)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    for field, value in [(Finding.severity, severity), (Finding.scanner, scanner), (Finding.status, status), (Finding.category, category)]:
        if value is not None:
            query = query.where(field == value)
    return db.scalars(query).all()


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: uuid.UUID, db: DB):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Находка не найдена")
    return finding


@router.get("/ai-analyses", response_model=list[AIAnalysisOut])
def list_analyses(db: DB, finding_id: uuid.UUID | None = None, limit: Limit = 100):
    query = select(AIAnalysis).order_by(AIAnalysis.created_at.desc()).limit(limit)
    if finding_id:
        query = query.where(AIAnalysis.finding_id == finding_id)
    return db.scalars(query).all()


@router.get("/fixes", response_model=list[FixOut])
def list_fixes(db: DB, finding_id: uuid.UUID | None = None, limit: Limit = 100):
    query = select(Fix).order_by(Fix.created_at.desc()).limit(limit)
    if finding_id:
        query = query.where(Fix.finding_id == finding_id)
    return db.scalars(query).all()


@router.get("/rescans", response_model=list[RescanOut])
def list_rescans(db: DB, project_id: uuid.UUID | None = None, limit: Limit = 100):
    query = select(Rescan).order_by(Rescan.created_at.desc()).limit(limit)
    if project_id:
        require_project(db, project_id)
        query = query.where(Rescan.project_id == project_id)
    return db.scalars(query).all()


@router.post("/scans", response_model=ScanOut, status_code=202)
def create_scan(data: ScanRequest, db: DB):
    # Serialize submissions in this shared demo workspace, including queue limits.
    db.scalar(select(User).where(User.id == WORKSPACE_USER_ID).with_for_update())
    repository = db.scalar(
        select(Repository)
        .where(Repository.id == data.repository_id)
        .with_for_update()
    )
    if repository is None:
        raise HTTPException(404, "Репозиторий не найден.")

    active_job = db.scalar(
        select(ScanJob.id)
        .join(Scan, Scan.id == ScanJob.scan_id)
        .where(
            Scan.repository_id == repository.id,
            ScanJob.status.in_(["QUEUED", "RUNNING"]),
        )
        .limit(1)
    )
    if active_job is not None:
        raise HTTPException(
            409,
            "Этот репозиторий уже ожидает проверки или сканируется.",
        )

    pending = db.scalar(select(func.count()).select_from(ScanJob).where(ScanJob.status.in_(["QUEUED", "RUNNING"]))) or 0
    if pending >= 10:
        raise HTTPException(429, "Очередь заполнена. Дождитесь завершения текущих проверок.")

    scan = Scan(
        project_id=repository.project_id,
        repository_id=repository.id,
        status=ScanStatus.QUEUED,
        scanner_config=scan_configuration(repository.default_branch),
    )
    db.add(scan)
    db.flush()

    db.add(ScanJob(scan_id=scan.id, status="QUEUED"))
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/rescans", status_code=501)
def create_rescan(data: RescanRequest):
    raise HTTPException(501, {"code": "SCANNERS_NOT_CONNECTED", "message": "Повторная проверка станет доступна после подключения сканеров."})

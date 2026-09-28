"""Opt-in public GitHub polling and comparable completed-scan history."""
import re
import uuid
from collections import Counter
from datetime import timedelta
from typing import Annotated
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from .api import require_project
from .auth import github_request, now
from .database import get_engine, get_session
from .models import AuditEvent, Finding, Repository, Scan, ScanJob, ScanStatus
from .risk import calculate
from .scanner_catalog import scan_configuration

router = APIRouter(prefix='/api')
DB = Annotated[Session, Depends(get_session)]


class ContinuousRequest(BaseModel):
    enabled: bool


@router.post('/repositories/{repository_id}/continuous')
def configure(repository_id: uuid.UUID, data: ContinuousRequest, db: DB):
    repo = db.get(Repository, repository_id)
    if repo is None:
        raise HTTPException(404, 'Репозиторий не найден.')
    repo.continuous_enabled = data.enabled
    db.add(AuditEvent(user_id=db.info.get('owner_id'), action='continuous_enabled' if data.enabled else 'continuous_disabled', object_id=str(repo.id), outcome='success'))
    db.commit()
    return {'enabled': repo.continuous_enabled, 'interval_seconds': 300}


def poll_once():
    """Called by the worker. API only persists configuration and jobs."""
    with Session(get_engine()) as db, db.begin():
        if not db.scalar(text('SELECT pg_try_advisory_xact_lock(820086)')):
            return
        if (db.scalar(select(func.count()).select_from(ScanJob).where(ScanJob.status.in_(('QUEUED', 'RUNNING')))) or 0) >= 10:
            return
        repo = db.scalar(select(Repository).where(Repository.continuous_enabled.is_(True), or_(
            Repository.last_checked_at.is_(None), Repository.last_checked_at < now() - timedelta(seconds=300)))
            .order_by(Repository.last_checked_at.asc().nullsfirst(), Repository.id).limit(1).with_for_update(skip_locked=True))
        if repo is None:
            return
        repo.last_checked_at = now()
        if db.scalar(select(ScanJob.id).join(Scan, ScanJob.scan_id == Scan.id).where(
            Scan.repository_id == repo.id, ScanJob.status.in_(('QUEUED', 'RUNNING'))).limit(1)):
            return
        slug = urlsplit(repo.url).path.strip('/').removesuffix('.git')
        try:
            result = github_request('/repos/' + slug + '/commits/' + quote(repo.default_branch, safe=''))
        except HTTPException:
            return  # Retry at the next bounded interval; never log upstream bodies.
        sha = result.get('sha', '')
        if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{40}', sha) or sha == repo.observed_sha:
            return
        config = scan_configuration(repo.default_branch)
        config.update(requested_commit=sha, trigger='continuous')
        scan = Scan(project_id=repo.project_id, repository_id=repo.id, scanner_config=config)
        db.add(scan)
        db.flush()
        db.add(ScanJob(scan_id=scan.id))
        repo.observed_sha = sha


def identity(f):
    meta = f.extra or {}
    return (f.scanner.value, f.category.value, f.rule_id, f.file, f.cve,
            meta.get('package'), meta.get('ecosystem'))


def compare(before, after):
    old, new = Counter(map(identity, before)), Counter(map(identity, after))
    return {'new': sum((new - old).values()), 'fixed': sum((old - new).values()), 'unchanged': sum((old & new).values())}


def security_score(findings):
    return max(0, 100 - round(sum(calculate(f, findings)['score'] for f in findings) / 10))


@router.get('/projects/{project_id}/security-history')
def history(project_id: uuid.UUID, db: DB):
    require_project(db, project_id)
    scans = db.scalars(select(Scan).where(Scan.project_id == project_id, Scan.kind == 'static',
        Scan.status == ScanStatus.COMPLETED).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(50)).all()
    groups, previous = [], {}
    for scan in reversed(scans):
        findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
        config = {k: v for k, v in scan.scanner_config.items() if k not in ('requested_commit', 'trigger')}
        key = (scan.repository_id, config.get('branch'))
        prior = previous.get(key)
        comparable = prior is not None and prior[1] == config
        groups.append({'scan_id': scan.id, 'repository_id': scan.repository_id, 'branch': config.get('branch'),
                       'commit_sha': scan.commit_sha, 'created_at': scan.created_at, 'security_score': security_score(findings),
                       'total': len(findings), 'comparison': compare(prior[2], findings) if comparable else None,
                       'baseline_scan_id': prior[0] if comparable else None})
        previous[key] = (scan.id, config, findings)
    return {'items': groups, 'score_policy': '100 − сумма базовых risk score / 10, минимум 0. Это индикатор объёма находок, не гарантия безопасности.',
            'comparison_policy': 'Только успешные статические проверки одной ветки и одной политики сканеров; Fixed означает, что совпадение больше не найдено.'}

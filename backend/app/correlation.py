"""AI hypotheses with frozen provenance; scanner records are never modified."""
import hashlib
import json
import re
from datetime import timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from . import ai_service as ai
from .config import get_settings
from .database import get_engine, get_session
from .models import AIAnalysis, CorrelationRun, Finding, Scan, SecurityIssueGroup
from .schemas import FindingOut
from .security_dashboard import check_project, latest_scans

router = APIRouter(prefix='/api')
MAX_FINDINGS = 12
Short = Annotated[str, Field(min_length=10, max_length=1200)]


class GroupProposal(BaseModel):
    model_config = ConfigDict(extra='forbid')
    title: str = Field(min_length=5, max_length=200)
    finding_refs: list[str] = Field(min_length=2, max_length=12)
    interpretation: Short
    verification: Short


class CorrelationOutput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    groups: list[GroupProposal] = Field(max_length=4)


PROMPT = """You are a security reviewer. Respond ONLY in RUSSIAN (русский язык), as JSON.
Review candidate groups of findings from one project. A shared file or package is context,
not proof of a shared cause. Select only candidates with a plausible common cause.
Copy finding_refs EXACTLY from one candidate; do not mix candidates or add other references.
Each candidate may be selected once. Do not invent vulnerabilities, endpoints or CVE details.
Write a short Russian title, a hypothetical common cause in interpretation and one manual
check in verification. Keep each field to ONE short sentence. Return {"groups": []} if uncertain.
Example of Russian wording (not actual evidence):
{"groups":[{"title":"Проблемы одной зависимости","finding_refs":["F1","F2"],
"interpretation":"Возможно, несколько находок связаны с устаревшей версией одного пакета.",
"verification":"Сверьте CVE и исправленные версии в исходных результатах сканера."}]}
Never copy the example's references unless they exactly match a supplied candidate.
Ответ только по-русски. Связь — предположение, требующее ручной проверки."""


def snapshot(db, project_id):
    scans = list(db.scalars(select(Scan.id).where(Scan.id.in_(latest_scans(project_id, completed_only=True))).order_by(Scan.id)))
    findings = list(db.scalars(select(Finding).where(Finding.project_id == project_id, Finding.scan_id.in_(scans)).order_by(Finding.id)))
    key = hashlib.sha256(json.dumps(['correlation-v2'] + [str(s) for s in scans] + [str(f.id) for f in findings]).encode()).hexdigest()
    return findings, key


def payload_for(findings):
    aliases = {'file': {}, 'repo': {}, 'package': {}}
    def alias(kind, value):
        if not value:
            return None
        return aliases[kind].setdefault(value, f'{kind}{len(aliases[kind]) + 1}')
    result = []
    for i, f in enumerate(findings):
        safe = ai.safe_finding(f)
        repo = str(f.scan_id)  # exactly one completed snapshot per repository
        result.append({'ref': f'F{i + 1}', **{k: safe[k] for k in ('scanner', 'category', 'severity', 'description', 'cve', 'cwe')},
                       'repo_ref': alias('repo', repo),
                       'file_ref': alias('file', (repo, f.file)) if f.file else None,
                       'package_ref': alias('package', (repo, f.extra.get('package'))) if f.extra.get('package') else None})
    candidates = []
    for kind in ('package_ref', 'file_ref'):
        for value in {f[kind] for f in result if f[kind]}:
            refs = [f['ref'] for f in result if f[kind] == value]
            if len(refs) >= 2 and refs not in [c['finding_refs'] for c in candidates]:
                candidates.append({'finding_refs': refs, 'shared_context': kind})
    return {'findings': result, 'candidates': candidates}


def validate_groups(data, finding_ids, payload=None):
    output = CorrelationOutput.model_validate(data)
    refs = {f'F{i + 1}': value for i, value in enumerate(finding_ids)}
    used = set()
    groups = []
    for proposal in output.groups:
        members = proposal.finding_refs
        if not all(re.search('[А-Яа-яЁё]', value) and not re.search('[\u4e00-\u9fff]', value)
                   for value in (proposal.title, proposal.interpretation, proposal.verification)):
            raise ValueError('Expected Russian hypothesis')
        if payload is not None and set(members) not in [set(c['finding_refs']) for c in payload['candidates']]:
            raise ValueError('Group lacks shared evidence context')
        if len(set(members)) != len(members) or any(m not in refs or m in used for m in members):
            raise ValueError('Invalid or duplicate finding references')
        used.update(members)
        groups.append({'title': proposal.title, 'interpretation': proposal.interpretation,
                       'verification': proposal.verification, 'finding_ids': [refs[m] for m in members]})
    return groups


def recover(db):
    db.execute(update(CorrelationRun).where(CorrelationRun.status == 'RUNNING',
        CorrelationRun.started_at < ai.now() - timedelta(seconds=get_settings().ai_timeout_seconds + 60)).values(
        status='FAILED', completed_at=ai.now(), error_message='Корреляция прервана. Повторите попытку.'))


def serialize(db, run, current_key=None):
    if not run:
        return None
    groups = []
    for group in db.scalars(select(SecurityIssueGroup).where(SecurityIssueGroup.run_id == run.id).order_by(SecurityIssueGroup.id)):
        evidence = db.scalars(select(Finding).where(Finding.project_id == run.project_id,
            Finding.id.in_([UUID(i) for i in group.finding_ids]))).all()
        groups.append({'id': group.id, 'title': group.title, 'ai_interpretation': group.interpretation,
            'verification': group.verification, 'scanner_evidence': [FindingOut.model_validate(f) for f in evidence]})
    return {'id': run.id, 'status': run.status, 'created_at': run.created_at, 'model': run.model,
            'total_findings': run.total_findings, 'analysed_findings': len(run.finding_ids),
            'stale': current_key is not None and run.snapshot_key != current_key,
            'error_message': run.error_message, 'groups': groups}


@router.get('/projects/{project_id}/correlation')
def get_correlation(project_id: UUID, db: Session = Depends(get_session)):
    check_project(db, project_id)
    recover(db)
    db.commit()
    _, key = snapshot(db, project_id)
    run = db.scalar(select(CorrelationRun).where(CorrelationRun.project_id == project_id).order_by(CorrelationRun.created_at.desc(), CorrelationRun.id.desc()).limit(1))
    return serialize(db, run, key)


@router.post('/projects/{project_id}/correlation', status_code=202)
def enqueue(project_id: UUID, db: Session = Depends(get_session)):
    if not get_settings().ai_enabled:
        raise HTTPException(503, 'Модель ещё не подключена.')
    check_project(db, project_id)
    db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': ai.QUEUE_LOCK})
    ai.recover(db)
    recover(db)
    findings, key = snapshot(db, project_id)
    previous = db.scalar(select(CorrelationRun).where(CorrelationRun.project_id == project_id,
        ((CorrelationRun.status.in_(['PENDING', 'RUNNING'])) |
         ((CorrelationRun.snapshot_key == key) & (CorrelationRun.status == 'COMPLETED')))).order_by(CorrelationRun.created_at.desc()).limit(1))
    if previous:
        db.commit()
        return serialize(db, previous, key)
    if len(findings) < 2:
        raise HTTPException(409, 'Нужны минимум две находки в последних успешных проверках проекта.')
    active = db.scalar(select(func.count()).select_from(CorrelationRun).where(CorrelationRun.status.in_(['PENDING', 'RUNNING'])))
    active += db.scalar(select(func.count()).select_from(AIAnalysis).where(AIAnalysis.status.in_(['PENDING', 'RUNNING'])))
    if active >= ai.MAX_ACTIVE:
        raise HTTPException(429, 'Очередь AI занята. Повторите позже.')
    run = CorrelationRun(project_id=project_id, snapshot_key=key, finding_ids=[str(f.id) for f in findings[:MAX_FINDINGS]],
                         total_findings=len(findings), model=get_settings().ai_model, status='PENDING')
    db.add(run)
    db.commit()
    db.refresh(run)
    return serialize(db, run, key)


def process_next():
    with Session(get_engine(), expire_on_commit=False) as db:
        db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': ai.QUEUE_LOCK})
        recover(db)
        ai.recover(db)
        if db.scalar(select(AIAnalysis.id).where(AIAnalysis.status == 'RUNNING').limit(1)) or db.scalar(select(CorrelationRun.id).where(CorrelationRun.status == 'RUNNING').limit(1)):
            db.commit()
            return False
        run = db.scalar(select(CorrelationRun).where(CorrelationRun.status == 'PENDING').order_by(CorrelationRun.created_at).limit(1).with_for_update(skip_locked=True))
        if not run:
            db.commit()
            return False
        ids = run.finding_ids
        found = {str(f.id): f for f in db.scalars(select(Finding).where(Finding.project_id == run.project_id, Finding.id.in_([UUID(i) for i in ids])))}
        if len(found) != len(ids):
            run.status, run.error_message = 'FAILED', 'Исходные находки больше недоступны.'
            db.commit()
            return True
        payload = payload_for([found[i] for i in ids])
        run.status, run.started_at = 'RUNNING', ai.now()
        run_id = run.id
        db.commit()
    try:
        output = ai.infer(payload, schema=CorrelationOutput, prompt=PROMPT)
        groups = validate_groups(output, ids, payload)
    except Exception:
        groups = None
    with Session(get_engine()) as db:
        run = db.scalar(select(CorrelationRun).where(CorrelationRun.id == run_id).with_for_update())
        if not run or run.status != 'RUNNING':
            return True
        if groups is None:
            run.status, run.error_message = 'FAILED', 'Модель недоступна или вернула некорректные связи. Повторите попытку.'
        else:
            db.add_all(SecurityIssueGroup(run_id=run.id, **g) for g in groups)
            run.status = 'COMPLETED'
        run.completed_at = ai.now()
        db.commit()
    ai.logger.info('AI_CORRELATION_%s id=%s', 'FAILED' if groups is None else 'COMPLETED', run_id)
    return True

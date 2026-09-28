"""Versioned, explainable prioritization; scanner severity remains immutable."""
import math
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .api import require_project
from .database import get_session
from .models import CorrelationRun, Finding, Scan, ScanStatus, SecurityIssueGroup
from .security_dashboard import latest_scans

POLICY = 'risk-v1'
BASE = {'CRITICAL': 65, 'HIGH': 50, 'MEDIUM': 30, 'LOW': 10, 'INFO': 0, 'UNKNOWN': 10}
router = APIRouter(prefix='/api')


def calculate(finding, peers=(), ai_related=False):
    reasons = []

    def add(factor, points, explanation):
        reasons.append({'factor': factor, 'points': points, 'explanation': explanation})

    add('severity', BASE[finding.severity], f'Уровень сканера: {finding.severity.value}')
    cvss = (finding.extra or {}).get('cvss_score')
    if type(cvss) in (int, float) and math.isfinite(cvss) and 0 <= cvss <= 10:
        add('cvss', round(cvss * 1.5), f'CVSS из отчёта Trivy: {cvss}')
    if finding.category == 'secret':
        add('secret', 15, 'Найден возможный секрет; его действительность не проверялась')
    if finding.scanner == 'nuclei' and finding.category == 'web':
        add('internet', 10, 'Проверка выполнена на разрешённом публичном HTTPS target')
    confirmations = {p.scanner.value for p in peers if p.id != finding.id and p.scanner != finding.scanner
                     and p.project_id == finding.project_id and p.scan_id == finding.scan_id
                     and finding.file and p.file == finding.file and finding.cwe and p.cwe == finding.cwe}
    if confirmations:
        add('confirmation', 10, 'Другие сканеры сообщили тот же CWE в том же файле: ' + ', '.join(sorted(confirmations)))
    if ai_related:
        add('ai_context', 2, 'AI предположил связь с другими находками; требуется проверка разработчика')
    score = min(100, sum(r['points'] for r in reasons))
    priority = next(label for threshold, label in ((80, 'P0'), (60, 'P1'), (35, 'P2'), (15, 'P3'), (0, 'P4')) if score >= threshold)
    return {'score': score, 'priority': priority, 'policy': POLICY, 'reasons': reasons}


def persist(findings, related_ids=()):
    related = set(related_ids)
    for finding in findings:
        result = calculate(finding, findings, str(finding.id) in related)
        finding.risk_score = result['score']
        finding.priority = result['priority']
        finding.risk_details = result


@router.post('/projects/{project_id}/prioritize')
def prioritize(project_id: uuid.UUID, db: Annotated[Session, Depends(get_session)]):
    require_project(db, project_id)
    findings = db.scalars(select(Finding).where(Finding.scan_id.in_(latest_scans(project_id, completed_only=True)))).all()
    current = {str(f.id) for f in findings}
    groups = db.scalars(select(SecurityIssueGroup).join(CorrelationRun, SecurityIssueGroup.run_id == CorrelationRun.id).where(
        CorrelationRun.project_id == project_id, CorrelationRun.status == 'COMPLETED')).all()
    related = {fid for group in groups if set(group.finding_ids).issubset(current) for fid in group.finding_ids}
    persist(findings, related)
    db.commit()
    return {'updated': len(findings), 'policy': POLICY}


@router.get('/projects/{project_id}/security-review')
def review(project_id: uuid.UUID, db: Annotated[Session, Depends(get_session)]):
    from .schemas import FindingOut
    require_project(db, project_id)
    findings = db.scalars(select(Finding).where(Finding.scan_id.in_(latest_scans(project_id, completed_only=True)))).all()
    # Historical results need an explicit refresh to persist the current policy.
    snapshots = db.scalars(select(Scan).where(Scan.id.in_(latest_scans(project_id, completed_only=True)))).all()
    attempts = db.scalars(select(Scan).where(Scan.id.in_(latest_scans(project_id)))).all()
    items = [(f, f.risk_details or calculate(f, findings)) for f in findings]
    items.sort(key=lambda item: (-item[1]['score'], str(item[0].id)))
    return {'has_successful_scan': bool(snapshots), 'previous_results': any(s.status == ScanStatus.FAILED for s in attempts),
            'total': len(items), 'important': sum(r['score'] >= 60 for _, r in items),
            'immediate': sum(r['score'] >= 80 for _, r in items), 'policy': POLICY,
            'issues': [{'finding': FindingOut.model_validate(f), 'risk': risk} for f, risk in items[:20]],
            'notice': 'Приоритет — оценка BultShield, а не severity сканера и не вероятность эксплуатации.'}

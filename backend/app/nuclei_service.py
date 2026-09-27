"""Three read-only HTTP header templates, exact operator allowlist and bounded requests."""
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .database import get_session
from .models import Category, Finding, Repository, Scan, ScanJob, Scanner, ScanStatus, Severity, WebTarget
from .scan_runtime import job_workspace, run_process, temporary_directory, timeout_seconds
from .security_dashboard import check_project
from .target_policy import TargetError, allowed_origins, allowed_target, canonical, pinned_proxy, pinned_target, preflight

router = APIRouter(prefix='/api')
VERSION = '3.11.1'
RULES_PATH = Path(__file__).resolve().parents[1] / 'rules' / 'nuclei'
RULES = {
    'bultshield-missing-nosniff': ('Не задан X-Content-Type-Options', 'X-Content-Type-Options: nosniff'),
    'bultshield-missing-frame-options': ('Не задана защита от встраивания во фрейм', 'X-Frame-Options или CSP frame-ancestors'),
    'bultshield-missing-hsts': ('Не задан Strict-Transport-Security', 'Strict-Transport-Security'),
}


class TargetInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    url: str = Field(max_length=2048)
    confirmed_control: bool


def target_out(target):
    return {'id': target.id, 'url': target.url, 'project_id': target.project_id,
            'allowed': target.url in allowed_origins(), 'confirmed_control': target.confirmed_control}


@router.get('/projects/{project_id}/targets')
def list_targets(project_id: UUID, db: Session = Depends(get_session)):
    check_project(db, project_id)
    return {'allowlist': sorted(allowed_origins()), 'templates': list(RULES), 'rate_per_second': 1,
            'items': [target_out(t) for t in db.scalars(select(WebTarget).where(WebTarget.project_id == project_id))]}


@router.post('/projects/{project_id}/targets', status_code=201)
def register_target(project_id: UUID, data: TargetInput, db: Session = Depends(get_session)):
    check_project(db, project_id)
    if not data.confirmed_control:
        raise HTTPException(422, 'Подтвердите право проверять этот test/staging-сервис.')
    try:
        url = allowed_target(data.url)
    except TargetError as exc:
        raise HTTPException(422, str(exc)) from None
    db.execute(text('SELECT pg_advisory_xact_lock(820083)'))
    existing = db.scalar(select(WebTarget).where(WebTarget.project_id == project_id, WebTarget.url == url))
    if existing:
        return target_out(existing)
    target = WebTarget(project_id=project_id, url=url, confirmed_control=True)
    db.add(target)
    db.commit()
    return target_out(target)


@router.post('/targets/{target_id}/scan', status_code=202)
def enqueue_web(target_id: UUID, db: Session = Depends(get_session)):
    db.execute(text('SELECT pg_advisory_xact_lock(820083)'))
    target = db.get(WebTarget, target_id)
    if not target:
        raise HTTPException(404, 'Адрес не найден.')
    try:
        allowed_target(target.url)
    except TargetError as exc:
        raise HTTPException(422, str(exc)) from None
    repo = db.scalar(select(Repository).where(Repository.project_id == target.project_id).order_by(Repository.created_at).limit(1))
    if not repo:
        raise HTTPException(409, 'Сначала добавьте репозиторий проекта.')
    active = db.scalar(select(Scan).join(ScanJob, ScanJob.scan_id == Scan.id).where(
        Scan.kind == 'web', Scan.target_url == target.url, ScanJob.status.in_(('QUEUED', 'RUNNING'))).limit(1))
    if active:
        return {'id': active.id, 'status': active.status}
    if db.scalar(select(func.count()).select_from(ScanJob).where(ScanJob.status.in_(('QUEUED', 'RUNNING')))) >= 10:
        raise HTTPException(429, 'Очередь проверок заполнена.')
    scan = Scan(project_id=target.project_id, repository_id=repo.id, kind='web', target_url=target.url,
                status=ScanStatus.QUEUED, scanner_config={'scanners': ['nuclei'], 'scope': 'allowlisted_staging',
                'branch': repo.default_branch, 'target_id': str(target.id), 'target_url': target.url,
                'nuclei_version': VERSION, 'templates': list(RULES), 'rate_per_second': 1})
    db.add(scan)
    db.flush()
    db.add(ScanJob(scan_id=scan.id, status='QUEUED'))
    db.commit()
    return {'id': scan.id, 'status': scan.status}


def parse_report(raw, origin, data):
    findings, seen = [], set()
    rows = json.loads(raw) if raw.lstrip().startswith('[') else [json.loads(line) for line in raw.splitlines() if line.strip()]
    if not isinstance(rows, list) or len(rows) > len(RULES):
        raise TargetError('Некорректный отчёт Nuclei.')
    for item in rows:
        rule = item.get('template-id')
        if rule not in RULES or item.get('type') != 'http' or canonical(item.get('matched-at', '')) != origin:
            raise TargetError('Nuclei вернул результат вне разрешённой политики.')
        if rule in seen:
            continue
        seen.add(rule)
        title, header = RULES[rule]
        findings.append(Finding(project_id=data.project_id, scan_id=data.scan_id, scanner=Scanner.NUCLEI,
            category=Category.WEB, severity=Severity.INFO, original_severity='info', title=title,
            description='Проверка HTTP-заголовка. Оцените необходимость настройки в контексте приложения.',
            file=None, rule_id=rule, evidence=f'GET /, HTTP 200: отсутствует {header}. Тело ответа и cookies не сохраняются.',
            fingerprint=hashlib.sha256((origin + ':' + rule).encode()).hexdigest(),
            extra={'target_url': origin, 'scanner_version': VERSION, 'scan_scope': 'allowlisted_staging', 'source_redacted': True}))
    return findings


def run_nuclei(origin, data):
    origin, host, ip = pinned_target(origin)
    executable = shutil.which('nuclei')
    if not executable:
        raise TargetError('Nuclei не установлен в worker.')
    preflight(host, ip)
    with temporary_directory(prefix='nuclei-') as tmp:
        root = Path(tmp)
        config, report, errors = root / 'config.yaml', root / 'report.jsonl', root / 'errors.log'
        config.write_text('{}\n')
        # Empty home/config: no cloud credentials, remote profiles or repository templates.
        environment = {'PATH': os.defpath, 'HOME': str(root), 'XDG_CONFIG_HOME': str(root), 'LANG': 'C.UTF-8', 'GOMAXPROCS': '1'}
        with pinned_proxy(host, ip) as (proxy, state):
            command = [executable, '-u', origin, '-t', str(RULES_PATH), '-config', str(config),
                '-jsonl', '-o', str(report), '-omit-raw', '-elog', str(errors), '-silent', '-nc',
                '-duc', '-no-interactsh', '-dr', '-nh', '-rl', '1', '-c', '1', '-bs', '1',
                '-timeout', '10', '-retries', '0', '-proxy', proxy, '-proxy-internal',
                '-response-size-read', '262144', '-response-size-save', '0']
            result = run_process(command, cwd=root, env=environment, timeout=timeout_seconds('NUCLEI_TIMEOUT_SECONDS', 90))
            if result.returncode or state['errors'] or not state['connections'] or errors.exists() and errors.stat().st_size:
                raise TargetError('Nuclei не завершил все разрешённые проверки. Результат неполный.')
        if not report.is_file() or report.stat().st_size > 1024 * 1024:
            raise TargetError('Отчёт Nuclei отсутствует или превышает лимит.')
        return parse_report(report.read_text(), origin, data)


def run_web_scan(data, progress, store):
    from .worker import sessions
    try:
        with sessions()() as db:
            target = db.get(WebTarget, UUID(data.config['target_id']))
            if not target or not target.confirmed_control or target.project_id != data.project_id or target.url != data.config['target_url']:
                raise TargetError('Разрешение на staging-проверку больше недоступно.')
        with job_workspace(data.job_id):
            progress(data, ScanStatus.SCANNING, step='nuclei', scanner_result=('nuclei', {'status': 'RUNNING'}))
            findings = run_nuclei(data.config['target_url'], data)
        progress(data, ScanStatus.ANALYSING, step='store')
        store(data, findings, {'nuclei': {'status': 'COMPLETED', 'version': VERSION, 'finding_count': len(findings),
              'template_count': len(RULES), 'scope': 'allowlisted_staging', 'rate_per_second': 1}})
    except (TargetError, OSError, ValueError, subprocess.TimeoutExpired):
        store(data, [], {'nuclei': {'status': 'FAILED', 'error': 'Nuclei: проверьте allowlist, HTTPS, DNS и доступность staging; полный результат не получен.', 'error_code': 'WEB_SCAN_FAILED'}})

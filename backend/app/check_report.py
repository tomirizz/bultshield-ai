"""Отчёт по проверке: измеренные факты, предположения и предложенные действия строго раздельно.

Статусы вычисляются из уже сохранённых данных. Проверка исправления в изолированной копии
никогда не выдаётся за исправление работающего приложения.
"""
from sqlalchemy import select

from .fix_runs import effective_status, latest_runs, now
from .fix_service import supported
from .image_history import compare_with_previous
from .llm_report import llm_assumptions, llm_section
from .models import AIAnalysis, Category, Finding, FindingStatus, Fix, LLMCall, LLMJob, ScanStatus

STATUS_TEXT = {
    'FOUND': 'Проблема обнаружена',
    'FIX_PROPOSED': 'Исправление предложено',
    'VERIFYING': 'Идёт проверка исправления',
    'FIX_VERIFIED': 'Исправление прошло проверку',
    'FIX_DEPLOYED': 'Исправление подтверждено в опубликованном образе',
    'MANUAL_REVIEW': 'Требуется ручное вмешательство',
}
RUNNING = (ScanStatus.QUEUED, ScanStatus.CLONING, ScanStatus.SCANNING, ScanStatus.ANALYSING,
           ScanStatus.NORMALIZING, ScanStatus.AI_ANALYSIS)
LIMITATIONS = (
    'Исправления проверяются в изолированной копии. Подтверждение исправления в опубликованном образе появляется, только если PR слит, '
    'образ собран после слияния и повторный скан нового образа больше не видит находку, а пакет в нём виден. '
    'Проверяется опубликованный образ: система не наблюдает, что именно он запущен в эксплуатации.',
    'Находки из базового образа и пакетов ОС в первой версии автоматически не исправляются.',
    'Отсутствие находок не гарантирует безопасность: проверена только область, которую охватывают сканеры.',
    'Пояснения языковой модели — предположения: они не проверялись сканерами и не влияют на статусы.',
)


def _verification_state(entry):
    item, combined = entry['item'], entry.get('combined')
    status = item.get('status')
    if status == 'fix_passed_verification':
        if item.get('needs_review'):
            return 'MANUAL_REVIEW', item.get('reason') or 'обновление требует просмотра человеком'
        if item.get('package') in ((combined or {}).get('packages') or []) and combined.get('outcome') == 'FIX_VERIFIED':
            return 'FIX_VERIFIED', None
        why = (combined or {}).get('reason') or 'совместная проверка набора обновлений не выполнялась'
        return 'FIX_PROPOSED', f'Обновление прошло проверку отдельно, но набор обновлений вместе не прошёл проверку: {why}'
    if status == 'fix_proposed':
        return 'FIX_PROPOSED', item.get('reason') or 'проверка исправления не завершена'
    if status == 'manual_intervention':
        return 'MANUAL_REVIEW', item.get('reason') or 'нужно ручное вмешательство'
    return 'MANUAL_REVIEW', 'результат агента исправлений не распознан'


def agent_state(entry):
    """Статус находки по результату агента исправлений зависимостей и причина (или None).

    «Прошло проверку» означает только проверку в песочнице. «Применено» требует доказательств (fix_deployment):
    слитый PR, новый образ, собранный после слияния, и повторный скан, в котором находки нет, а пакет виден.
    Всё неясное или неизвестное даёт ручной разбор, а не «исправлено».
    """
    if entry.get('phase') == 'running':
        return 'VERIFYING', 'Идёт проверка обновления в песочнице.'
    state, reason = _verification_state(entry)
    proof, info = entry.get('deployment'), entry.get('deployment_info') or {}
    if proof and state == 'FIX_VERIFIED':
        if proof.get('state') == 'gone' and info.get('status') == 'CONFIRMED':
            pull = info.get('pull_request') or {}
            return 'FIX_DEPLOYED', (f"PR №{pull.get('number')} слит, образ {info.get('image_digest')} собран после слияния и просканирован "
                                    'повторно: находка не обнаруживается, пакет в образе виден. Проверен опубликованный образ.')
        if proof.get('state') == 'still_detected':
            return 'MANUAL_REVIEW', 'После слияния PR и пересборки образа находка осталась.'
        if proof.get('state') == 'not_seen':
            return state, 'Применение не подтверждено: пакет не виден в отчёте повторной проверки образа.'
    return state, reason


def finding_state(finding, fix=None, agent=None):
    """Статус находки по ТЗ и причина (или None). Причина ручного разбора или пояснение к статусу."""
    extra = finding.extra or {}
    if finding.status == FindingStatus.STILL_DETECTED:
        return 'MANUAL_REVIEW', 'после применения исправления находка осталась'
    if fix is not None and fix.status == 'FAILED' and (fix.verification or {}).get('outcome') == 'INCONCLUSIVE':
        return 'MANUAL_REVIEW', fix.error_message or 'проверка исправления не завершилась, результат не определён'
    if finding.status == FindingStatus.VERIFIED_FIXED:
        return 'FIX_VERIFIED', None
    if finding.status in (FindingStatus.FIX_APPLIED, FindingStatus.RECHECKING):
        return 'VERIFYING', None
    if finding.status == FindingStatus.FIX_PROPOSED:
        return 'FIX_PROPOSED', None
    if agent is not None:
        return agent_state(agent)
    if extra.get('manual_reason'):
        return 'MANUAL_REVIEW', extra['manual_reason']
    if not supported(finding):
        return 'MANUAL_REVIEW', 'автоматическое исправление для этого типа находок не поддерживается'
    if finding.category == Category.DEPENDENCY and not extra.get('fixed_version'):
        return 'MANUAL_REVIEW', 'исправленной версии нет'
    return 'FOUND', None


def verdict(scan, total):
    results = scan.scanner_results or {}
    if scan.status in RUNNING:
        return 'IN_PROGRESS', 'Проверка ещё выполняется.'
    if scan.status == ScanStatus.FAILED or not results or any((r or {}).get('status') == 'FAILED' for r in results.values()):
        return 'INCOMPLETE', 'Проверка выполнена не полностью. Отсутствие находок в этом отчёте не означает отсутствие уязвимостей.'
    if total:
        return 'FINDINGS', f'Сканеры нашли проблем: {total}.'
    return 'NO_FINDINGS', 'Сканеры не нашли проблем в проверенной области. Это не гарантия безопасности.'


def action(finding, state, reason, agent=None, pull_request=None):
    extra = finding.extra or {}
    if agent is not None and agent.get('phase') != 'running':
        if state == 'FIX_VERIFIED' and pull_request:
            return {'action': 'review_pull_request', 'detail': (
                f"PR создан: {pull_request['url']}. Слияние выполняет человек. После слияния образ нужно пересобрать, "
                'опубликовать и просканировать повторно: до этого работающее приложение не исправлено.')}
        if state == 'FIX_VERIFIED':
            return {'action': 'create_pull_request', 'detail': (
                'После подтверждения человеком создать PR с обновлением. Проверка проходила только в изолированной копии.')}
        if state == 'FIX_PROPOSED':
            return {'action': 'rerun_verification', 'detail': reason}
    if state == 'MANUAL_REVIEW':
        return {'action': 'manual_review', 'detail': reason}
    if state == 'FOUND':
        if extra.get('source') == 'image':
            return {'action': 'update_dependency', 'detail': (
                f"Сканер указывает исправленную версию: {extra.get('fixed_version')}. Автоматическая подготовка "
                'исправления для находок образа пока не реализована.')}
        return {'action': 'generate_fix', 'detail': 'Запросить предложение исправления: POST /api/findings/{id}/fix.'}
    if state == 'FIX_PROPOSED':
        return {'action': 'review_and_approve', 'detail': 'Просмотреть diff и подтвердить проверку в изолированной копии.'}
    if state == 'FIX_VERIFIED':
        return {'action': 'apply_after_review', 'detail': (
            'Применить исправление в репозитории и пересобрать образ. Проверка проходила только в изолированной копии.')}
    return None


def fix_summary(fix):
    return {'id': str(fix.id), 'status': fix.status, 'scope': 'isolated_copy', 'applied_to_running_app': False,
            'outcome': (fix.verification or {}).get('outcome'), 'verification': fix.verification or {},
            'diff': fix.diff, 'timeline': fix.timeline or []}


def agent_summary(entry, run):
    """Проверка опубликованного образа не доказывает, что он запущен в эксплуатации."""
    if entry.get('phase') == 'running':
        return {'source': 'dependency_agent', 'run_id': str(run.id), 'status': 'verifying', 'scope': 'isolated_copy',
                'applied_to_running_app': False}
    item = entry['item']
    verification = item.get('verification') or {}
    proof = entry.get('deployment')
    applied = bool(proof and proof.get('state') == 'gone' and (entry.get('deployment_info') or {}).get('status') == 'CONFIRMED')
    return {'source': 'dependency_agent', 'run_id': str(run.id), 'status': item.get('status'),
            'scope': 'published_image' if applied else 'isolated_copy', 'applied_to_running_app': False,
            'published_image_verified': applied,
            'package': item.get('package'), 'installed_version': item.get('installed'),
            'target_version': item.get('target'), 'major_change': item.get('major_change'),
            'needs_review': item.get('needs_review'), 'reason': item.get('reason'), 'outcome': verification.get('outcome'),
            'method': verification.get('method'), 'diff': verification.get('diff'), 'verification': verification,
            'deployment': proof}


def version_choices(run):
    """Кто и как выбрал версию для каждого пакета: модель (и принят ли её выбор после проверки) или правила. Без запуска модели список пуст."""
    result = []
    for item in (run.items or []):
        llm = item.get('llm_plan')
        if not llm or not item.get('target'):
            continue
        result.append({'package': item['package'], 'installed': item.get('installed'), 'rule_target': llm.get('default'),
                       'final_target': llm.get('final_target') or item.get('target'), 'model_target': llm.get('target'),
                       'status': llm.get('status'), 'accepted': llm.get('accepted'),
                       'agreed_with_rules': llm.get('target') == llm.get('default'), 'chosen_by': 'model' if llm.get('accepted') else 'rules',
                       'reason': llm.get('reason'), 'risk': llm.get('risk'), 'needs_review': bool(llm.get('needs_review')),
                       'rejected_outcome': llm.get('rejected_outcome'), 'message': llm.get('message'), 'model': llm.get('model'),
                       'input_tokens': llm.get('input_tokens', 0), 'output_tokens': llm.get('output_tokens', 0)})
    return result


def run_summary(run, current):
    """Сводка запуска агента для отчёта: что проверялось, на каком коде и образе, чем закончилось."""
    if run is None:
        return None
    combined = run.combined or None
    return {'id': str(run.id), 'status': effective_status(run, current), 'scope': 'isolated_copy', 'applied_to_running_app': False,
            'commit_sha': run.commit_sha, 'image_digest': run.image_digest, 'summary': run.summary or {},
            'combined': ({key: combined.get(key) for key in ('packages', 'outcome', 'reason', 'scan_db_updated_at')}
                         if combined else None),
            'version_choices': version_choices(run), 'pull_request': run.pull_request, 'error_message': run.error_message,
            'started_at': run.started_at.isoformat() if run.started_at else None,
            'completed_at': run.completed_at.isoformat() if run.completed_at else None}


def deployment_summary(run):
    """Итог последней проверки применения: что подтверждено и чего не хватает."""
    if run is None or not run.deployment:
        return None
    data = run.deployment
    return {'run_id': str(run.id), 'status': data.get('status'), 'scope': 'published_image', 'checked_at': data.get('checked_at'),
            'rescan_id': data.get('rescan_id'), 'image_digest': data.get('image_digest'),
            'base_image_digest': data.get('base_image_digest'), 'image_created': data.get('image_created'),
            'pull_request': data.get('pull_request'), 'reasons': data.get('reasons') or [], 'counts': data.get('counts') or {},
            'last_attempt': data.get('last_attempt')}


def agent_entries(scan, findings, fix_runs, current):
    """finding.id -> результат агента для этой находки. Запуск по другому образу не учитывается."""
    runs = fix_runs or {}
    latest, completed, evaluated = runs.get('latest'), runs.get('completed'), runs.get('evaluated')
    digest = ((scan.scanner_results or {}).get('trivy') or {}).get('digest')

    def usable(run):
        return run is not None and not (run.image_digest and digest and run.image_digest != digest)

    def items_by_finding(run):
        return {fid: item for item in (run.items if usable(run) else []) or [] for fid in item.get('finding_ids') or []}

    proofs = ((evaluated.deployment or {}).get('findings') or {}) if usable(evaluated) else {}
    evaluated_items = items_by_finding(evaluated)
    completed_items = items_by_finding(completed)
    running = latest is not None and effective_status(latest, current) == 'RUNNING'
    entries = {}
    for finding in findings:
        key, extra = str(finding.id), finding.extra or {}
        if key in proofs and key in evaluated_items:
            entries[finding.id] = {'item': evaluated_items[key], 'combined': evaluated.combined, 'run': evaluated,
                                   'deployment': proofs[key], 'deployment_info': evaluated.deployment}
        elif running:
            if extra.get('origin') == 'app' and not extra.get('manual_reason'):
                entries[finding.id] = {'phase': 'running', 'run': latest}
        elif key in completed_items:
            entries[finding.id] = {'item': completed_items[key], 'combined': completed.combined, 'run': completed}
    return entries


def build_report(scan, findings, fixes=None, analyses=None, limit=100, offset=0, fix_runs=None, current=None, llm_calls=None, changes=None, llm_job=None):
    """findings уже отсортированы. fixes и analyses: словари finding_id -> последняя запись.

    fix_runs: {'latest': запуск агента, 'completed': последний завершённый запуск} или None.
    """
    fixes, analyses = fixes or {}, analyses or {}
    current = current or now()
    agents = agent_entries(scan, findings, fix_runs, current)
    states = [finding_state(f, fixes.get(f.id), agents.get(f.id)) for f in findings]
    by_status, by_severity, by_origin = {}, {}, {}
    for finding, (state, _) in zip(findings, states, strict=True):
        by_status[state] = by_status.get(state, 0) + 1
        by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
        origin = (finding.extra or {}).get('origin')
        if origin:
            by_origin[origin] = by_origin.get(origin, 0) + 1
    kind, statement = verdict(scan, len(findings))
    config, results = scan.scanner_config or {}, scan.scanner_results or {}
    page = list(zip(findings, states, strict=True))[offset:offset + limit]
    items, assumptions, actions = [], [], []
    for finding, (state, reason) in page:
        extra = finding.extra or {}
        fix = fixes.get(finding.id)
        entry = agents.get(finding.id)
        items.append({
            'id': str(finding.id), 'title': finding.title, 'rule_id': finding.rule_id, 'cve': finding.cve,
            'severity': finding.severity.value, 'risk_score': finding.risk_score, 'priority': finding.priority,
            'component': extra.get('package') or finding.file, 'file': finding.file,
            'installed_version': extra.get('installed_version'), 'fixed_version': extra.get('fixed_version'),
            'scanner': finding.scanner.value, 'category': finding.category.value, 'source': extra.get('source') or 'repository',
            'origin': extra.get('origin'), 'status': state, 'status_text': STATUS_TEXT[state], 'status_reason': reason,
            'manual_reason': reason if state == 'MANUAL_REVIEW' else None,
            'fix': fix_summary(fix) if fix is not None else (agent_summary(entry, entry['run']) if entry is not None else None),
        })
        proposal = action(finding, state, reason, entry, (entry['run'].pull_request if entry is not None else None))
        if proposal:
            actions.append({'finding_id': str(finding.id), **proposal})
        analysis = analyses.get(finding.id)
        if analysis is not None:
            assumptions.append({'finding_id': str(finding.id), 'source': 'ai_analysis', 'model': analysis.model,
                                'explanation': (analysis.explanation or '')[:2000],
                                'recommended_fix': (analysis.recommended_fix or '')[:2000]})
        if fix is not None and fix.description:
            assumptions.append({'finding_id': str(finding.id), 'source': 'ai_fix_explanation', 'model': None,
                                'explanation': fix.description[:2000], 'recommended_fix': None})
    return {
        'check': {'id': str(scan.id), 'kind': scan.kind, 'status': scan.status.value, 'error_code': scan.error_code,
                  'error_message': scan.error_message,
                  'created_at': scan.created_at.isoformat() if scan.created_at else None,
                  'completed_at': scan.completed_at.isoformat() if scan.completed_at else None},
        'subject': {'repository_id': str(scan.repository_id), 'commit_sha': scan.commit_sha,
                    'requested_commit': config.get('requested_commit'), 'trigger': config.get('trigger'),
                    'watched': bool(config.get('watch')),
                    'image': (config.get('image') or {}).get('reference'),
                    'image_digest': (results.get('trivy') or {}).get('digest')},
        'verdict': {'result': kind, 'statement': statement},
        'facts': {'scanners': results, 'total_findings': len(findings), 'by_severity': by_severity,
                  'by_origin': by_origin, 'by_status': by_status},
        'findings': {'items': items, 'limit': limit, 'offset': offset, 'total': len(findings)},
        'changes_since_previous': changes,
        'fix_run': run_summary((fix_runs or {}).get('latest'), current),
        'deployment': deployment_summary((fix_runs or {}).get('evaluated')),
        'assumptions': assumptions + llm_assumptions(llm_calls or [], [i['id'] for i in items]),
        'llm': llm_section(llm_calls or [], llm_job),
        'proposed_actions': actions,
        'limitations': list(LIMITATIONS),
    }


def load_report(db, scan, limit=100, offset=0):
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)
                          .order_by(Finding.risk_score.desc().nullslast(), Finding.id)).all()
    ids = [f.id for f in findings]
    fixes, analyses = {}, {}
    if ids:
        for fix in db.scalars(select(Fix).where(Fix.finding_id.in_(ids)).order_by(Fix.created_at.desc(), Fix.id.desc())):
            fixes.setdefault(fix.finding_id, fix)
        for item in db.scalars(select(AIAnalysis).where(AIAnalysis.finding_id.in_(ids), AIAnalysis.status == 'COMPLETED')
                               .order_by(AIAnalysis.created_at.desc(), AIAnalysis.id.desc())):
            analyses.setdefault(item.finding_id, item)
    calls = db.scalars(select(LLMCall).where(LLMCall.scan_id == scan.id).order_by(LLMCall.created_at.desc(), LLMCall.id.desc())).all()
    return build_report(scan, findings, fixes, analyses, limit, offset, latest_runs(db, scan.id), llm_calls=calls,
                        changes=compare_with_previous(db, scan, findings), llm_job=db.scalar(select(LLMJob).where(LLMJob.scan_id == scan.id).order_by(LLMJob.created_at.desc(), LLMJob.id.desc()).limit(1)))

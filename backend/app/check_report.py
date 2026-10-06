"""Отчёт по проверке: измеренные факты, предположения и предложенные действия строго раздельно.

Статусы вычисляются из уже сохранённых данных. Проверка исправления в изолированной копии
никогда не выдаётся за исправление работающего приложения.
"""
from sqlalchemy import select

from .fix_service import supported
from .models import AIAnalysis, Category, Finding, FindingStatus, Fix, ScanStatus

STATUS_TEXT = {
    'FOUND': 'Проблема обнаружена',
    'FIX_PROPOSED': 'Исправление предложено',
    'VERIFYING': 'Идёт проверка исправления',
    'FIX_VERIFIED': 'Исправление прошло проверку',
    'FIX_DEPLOYED': 'Исправление применено к приложению',
    'MANUAL_REVIEW': 'Требуется ручное вмешательство',
}
RUNNING = (ScanStatus.QUEUED, ScanStatus.CLONING, ScanStatus.SCANNING, ScanStatus.ANALYSING,
           ScanStatus.NORMALIZING, ScanStatus.AI_ANALYSIS)
LIMITATIONS = (
    'Исправления проверяются только в изолированной копии. Статус «применено к приложению» означает, что '
    'исправление слито, образ пересобран, и повторный скан опубликованного образа больше не видит находку. '
    'Эта часть пока не реализована, поэтому такой статус сейчас не присваивается.',
    'Находки из базового образа и пакетов ОС в первой версии автоматически не исправляются.',
    'Отсутствие находок не гарантирует безопасность: проверена только область, которую охватывают сканеры.',
)


def finding_state(finding, fix=None):
    """Статус находки по ТЗ и причина ручного разбора (или None)."""
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


def action(finding, state, reason):
    extra = finding.extra or {}
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


def build_report(scan, findings, fixes=None, analyses=None, limit=100, offset=0):
    """findings уже отсортированы. fixes и analyses: словари finding_id -> последняя запись."""
    fixes, analyses = fixes or {}, analyses or {}
    states = [finding_state(f, fixes.get(f.id)) for f in findings]
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
        items.append({
            'id': str(finding.id), 'title': finding.title, 'rule_id': finding.rule_id, 'cve': finding.cve,
            'severity': finding.severity.value, 'risk_score': finding.risk_score, 'priority': finding.priority,
            'component': extra.get('package') or finding.file, 'file': finding.file,
            'installed_version': extra.get('installed_version'), 'fixed_version': extra.get('fixed_version'),
            'scanner': finding.scanner.value, 'category': finding.category.value, 'source': extra.get('source') or 'repository',
            'origin': extra.get('origin'), 'status': state, 'status_text': STATUS_TEXT[state], 'manual_reason': reason,
            'fix': fix_summary(fix) if fix is not None else None,
        })
        proposal = action(finding, state, reason)
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
                    'image': (config.get('image') or {}).get('reference'),
                    'image_digest': (results.get('trivy') or {}).get('digest')},
        'verdict': {'result': kind, 'statement': statement},
        'facts': {'scanners': results, 'total_findings': len(findings), 'by_severity': by_severity,
                  'by_origin': by_origin, 'by_status': by_status},
        'findings': {'items': items, 'limit': limit, 'offset': offset, 'total': len(findings)},
        'assumptions': assumptions,
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
    return build_report(scan, findings, fixes, analyses, limit, offset)

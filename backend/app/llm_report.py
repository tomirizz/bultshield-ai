"""Как пояснения модели показываются в отчёте: отдельно от фактов и без влияния на статусы."""

LIMIT_KEY = '*limit'
NOTE = 'Пояснения модели — предположения. Они не проверялись сканерами, не меняют статусы и не заменяют результаты проверки.'
MAX_FAILURES = 10


def _latest(calls):
    """Последний запрос по каждому предмету пояснения. calls идут от новых к старым."""
    latest = {}
    for call in calls:
        if call.subject_key != LIMIT_KEY:
            latest.setdefault(call.subject_key, call)
    return latest


def llm_assumptions(calls, finding_ids):
    """Пояснения для находок текущей страницы отчёта: по одному на группу находок (пакет), а не на каждую находку."""
    shown, result = set(finding_ids), []
    for subject, call in _latest(calls).items():
        if call.status != 'COMPLETED' or not call.result or not shown.intersection(call.finding_ids or []):
            continue
        result.append({'finding_id': None, 'finding_ids': list(call.finding_ids), 'source': 'llm_explanation', 'subject': subject,
                       'model': call.model, 'explanation': str(call.result.get('summary', ''))[:2000],
                       'risk': str(call.result.get('risk', ''))[:2000], 'recommended_fix': str(call.result.get('recommendation', ''))[:2000],
                       'call_id': str(call.id)})
    return result


def job_brief(job):
    if job is None:
        return None
    return {'id': str(job.id), 'status': job.status, 'created_at': job.created_at.isoformat() if job.created_at else None,
            'completed_at': job.completed_at.isoformat() if job.completed_at else None, 'error': job.error_message}


def llm_section(calls, job=None):
    """job: последнее фоновое задание на пояснения (или None). Пока оно идёт, отчёт не должен выглядеть так, будто пояснений не будет."""
    section = _section(calls)
    section['job'] = job_brief(job)
    if job is not None and job.status in ('QUEUED', 'RUNNING') and not calls:
        section.update(status='PENDING', message='Пояснения модели запрашиваются: задание в очереди или выполняется.')
    elif job is not None and job.status == 'FAILED' and not calls:
        section.update(status='FAILED', message=f'Задание на пояснения не выполнено: {job.error_message} Результаты сканеров и статусы от этого не зависят.')
    return section


def _section(calls):
    if not calls:
        return {'status': 'NOT_RUN', 'message': 'Пояснения модели не запрашивались.', 'note': NOTE, 'explained': 0, 'failed': 0,
                'provider': None, 'model': None, 'input_tokens': 0, 'output_tokens': 0, 'cost_usd': 0.0, 'failures': []}
    latest = _latest(calls)
    explained = [c for c in latest.values() if c.status == 'COMPLETED']
    failed = [c for c in latest.values() if c.status != 'COMPLETED']
    # Лимит показывается, только если он остановил самый последний запуск: позднее полученные пояснения его снимают.
    limited = calls[0].status == 'LIMIT_EXCEEDED'
    if not latest:
        status, message = 'LIMITED', 'Достигнут лимит запросов к модели: пояснения не запрашивались.'
    elif not failed and not limited:
        status, message = 'COMPLETED', f'Модель пояснила групп находок: {len(explained)}.'
    elif explained:
        status = 'PARTIAL'
        message = f'Пояснено групп находок: {len(explained)}; для остальных пояснения нет (причины ниже). Статусы и факты от этого не зависят.'
    elif any(c.status == 'UNAVAILABLE' for c in failed):
        status = 'UNAVAILABLE'
        message = 'Модель недоступна, пояснений нет. Результаты сканеров, статусы и предложенные действия от этого не зависят.'
    else:
        status, message = 'FAILED', 'Модель не дала пригодного ответа, пояснений нет. Результаты сканеров и статусы от этого не зависят.'
    newest = calls[0]
    failures = [{'subject': c.subject_key, 'status': c.status, 'error_code': c.error_code, 'message': c.error_message}
                for c in failed[:MAX_FAILURES]]
    if limited:
        failures.append({'subject': LIMIT_KEY, 'status': 'LIMIT_EXCEEDED', 'error_code': 'limit',
                         'message': calls[0].error_message})
    return {'status': status, 'message': message, 'note': NOTE, 'explained': len(explained), 'failed': len(failed),
            'provider': newest.provider, 'model': newest.model,
            'input_tokens': sum(c.input_tokens or 0 for c in calls), 'output_tokens': sum(c.output_tokens or 0 for c in calls),
            'cost_usd': float(sum(float(c.cost_usd or 0) for c in calls)), 'failures': failures}

"""Подтверждение того, что проверенное исправление применено: доказательства вместо предположений.

Статус «исправление применено» ставится находке, только если выполнены все условия:
  1. GitHub подтверждает, что PR этого запуска слит (а не просто создан);
  2. повторно просканирован новый образ: другой digest, и образ собран после слияния PR;
  3. в повторном скане находка (идентификатор уязвимости и пакет) больше не обнаруживается;
  4. в том же скане виден сам пакет. Иначе «исчезла» могло получиться из-за того, что Trivy не увидел приложение.
Если чего-то не хватает, находка остаётся «прошла проверку», а причина записывается. Сбой GitHub или некорректный
скан не превращается в «применено»: запуск отклоняется с понятной причиной, прежние результаты не меняются.
Проверяется опубликованный образ. Что именно он запущен в эксплуатации, система не наблюдает.
"""
from sqlalchemy import select

from .fix_agent import FIX_PASSED
from .fix_runs import FixRunError, now
from .github_pr import GitHubError, fetch_pull_request
from .image_report import parse_time
from .models import DependencyFixRun, Finding, Scan, ScanStatus

GONE, STILL, NOT_SEEN = 'gone', 'still_detected', 'not_seen'
CONFIRMED, NOT_CONFIRMED = 'CONFIRMED', 'NOT_CONFIRMED'


def _included(run):
    """Элементы запуска, обновления которых вошли в PR: прошли проверку, не требуют просмотра и проверены набором."""
    combined = run.combined or {}
    if combined.get('outcome') != 'FIX_VERIFIED':
        return []
    return [i for i in run.items or [] if i.get('status') == FIX_PASSED and not i.get('needs_review')
            and i.get('package') in (combined.get('packages') or [])]


def _load(db, run_id):
    run = db.scalar(select(DependencyFixRun).where(DependencyFixRun.id == run_id).with_for_update())
    if run is None:
        raise FixRunError('Запуск не найден.')
    if run.status != 'COMPLETED':
        raise FixRunError('Подтверждать применение можно только для завершённого запуска.')
    pull = run.pull_request or {}
    if not pull.get('repo') or not pull.get('number'):
        raise FixRunError('К запуску не привязан PR: сначала создайте PR из этого запуска.')
    return run


def _rescan(db, run, base, rescan_id):
    scan = db.get(Scan, rescan_id)
    if scan is None:
        raise FixRunError('Повторная проверка не найдена.')
    if scan.kind != 'image':
        raise FixRunError('Подтверждение возможно только по проверке образа.')
    if scan.id == base.id:
        raise FixRunError('Нужна новая проверка образа, а не та, по которой строился запуск.')
    if scan.project_id != base.project_id or scan.repository_id != base.repository_id:
        raise FixRunError('Повторная проверка относится к другому репозиторию.')
    ours = (base.scanner_config.get('image') or {}).get('repository')
    theirs = (scan.scanner_config.get('image') or {}).get('repository')
    if not ours or ours != theirs:
        raise FixRunError('Повторно проверен другой образ (другой репозиторий образов).')
    trivy = (scan.scanner_results or {}).get('trivy') or {}
    if scan.status != ScanStatus.COMPLETED or trivy.get('status') != 'COMPLETED':
        raise FixRunError('Повторная проверка образа не завершилась успешно: результат не определён.')
    return scan, trivy


def _reasons(run, pr, trivy):
    """Чего не хватает для подтверждения. Пустой список: все условия по PR и образу выполнены."""
    reasons = []
    if not pr['merged']:
        reasons.append('PR ещё не слит: слияние выполняет человек, до него исправление не применено.')
    if pr['head_ref'] != (run.pull_request or {}).get('branch'):
        reasons.append('Ветка PR на GitHub не совпадает с веткой, созданной этим запуском.')
    digest = trivy.get('digest')
    if not digest:
        reasons.append('В отчёте повторной проверки нет digest образа.')
    elif digest == run.image_digest:
        reasons.append('Образ не менялся: digest тот же, что у исходной проверки. Пересоберите и опубликуйте образ.')
    created, merged = parse_time(trivy.get('image_created')), parse_time(pr['merged_at'])
    if created is None:
        reasons.append('В отчёте повторной проверки нет времени сборки образа: нельзя убедиться, что образ собран после слияния PR.')
    elif merged is not None and created < merged:
        reasons.append('Образ собран раньше слияния PR: пересоберите образ из слитого кода.')
    return reasons


def _evaluate(run, rows, rescan_rows, trivy):
    """Для каждой находки из PR: исчезла / осталась / пакет в новом образе не виден."""
    present = {((r.extra or {}).get('package'), r.rule_id) for r in rescan_rows if (r.extra or {}).get('origin') == 'app'}
    seen = {}
    for package in trivy.get('app_packages') or []:
        seen.setdefault(package.get('name'), set()).add(package.get('version'))
    truncated = trivy.get('app_packages_truncated') is not False   # нет признака полноты: считаем список неполным
    result = {}
    for item in _included(run):
        for finding_id in item.get('finding_ids') or []:
            row = rows.get(finding_id)
            if row is None:
                continue
            package = (row.extra or {}).get('package')
            if (package, row.rule_id) in present:
                state = STILL
            elif truncated or package not in seen:
                state = NOT_SEEN
            else:
                state = GONE
            result[finding_id] = {'state': state, 'package': package, 'rule_id': row.rule_id,
                                  'seen_versions': sorted(seen.get(package, ()))[:10]}
    return result


def confirm_deployment(db, run_id, rescan_id, client):
    """Проверяет доказательства применения исправления и записывает результат в запуск. Возвращает запуск."""
    run = _load(db, run_id)
    base = db.get(Scan, run.scan_id)
    scan, trivy = _rescan(db, run, base, rescan_id)
    pull = run.pull_request
    try:
        pr = fetch_pull_request(client, pull['repo'], pull['number'])
    except GitHubError as exc:
        raise FixRunError(f'Не удалось проверить PR на GitHub: {exc}') from None
    reasons = _reasons(run, pr, trivy)
    findings = {}
    if not reasons:
        rows = {str(r.id): r for r in db.scalars(select(Finding).where(Finding.scan_id == base.id))}
        rescan_rows = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
        findings = _evaluate(run, rows, rescan_rows, trivy)
        if not findings:
            reasons.append('В запуске нет находок, обновления которых вошли в PR.')
    counts = {state: sum(1 for f in findings.values() if f['state'] == state) for state in (GONE, STILL, NOT_SEEN)}
    if not reasons and counts[NOT_SEEN]:
        reasons.append(f'Для находок без подтверждения ({counts[NOT_SEEN]}) пакет не виден в отчёте повторной проверки.')
    if not reasons and counts[STILL]:
        reasons.append(f'После слияния и пересборки находок осталось: {counts[STILL]}.')
    deployment = {
        'status': CONFIRMED if counts[GONE] else NOT_CONFIRMED, 'checked_at': now().isoformat(), 'rescan_id': str(scan.id),
        'image_digest': trivy.get('digest'), 'base_image_digest': run.image_digest, 'image_created': trivy.get('image_created'),
        'image_revision': trivy.get('image_revision'), 'scope': 'published_image',
        'pull_request': {key: pr[key] for key in ('number', 'url', 'merged', 'merged_at', 'merge_commit_sha')},
        'reasons': reasons, 'counts': counts, 'findings': findings,
    }
    old = run.deployment or {}
    if old.get('status') == CONFIRMED and deployment['status'] != CONFIRMED:
        # Неудачная повторная попытка не отменяет уже полученное доказательство.
        deployment = {**old, 'last_attempt': {key: deployment[key] for key in ('status', 'checked_at', 'rescan_id', 'reasons')}}
    run.pull_request = {**pull, 'merged': pr['merged'], 'merged_at': pr['merged_at'], 'merge_commit_sha': pr['merge_commit_sha']}
    run.deployment = deployment
    db.commit()
    return run

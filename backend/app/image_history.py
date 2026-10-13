"""Что изменилось по сравнению с предыдущей проверкой того же образа.

Нужно для перепроверок: если образ тот же, а находки новые, значит появились новые данные об уязвимостях (база Trivy обновилась),
а не изменился сам образ. Сравнивать с неудачной или неполной проверкой нельзя, поэтому берётся только последняя завершённая.
"""
from sqlalchemy import select, tuple_

from .models import Finding, Scan, ScanStatus

MAX_LISTED = 20


def _key(finding):
    meta = finding.extra or {}
    # У пакетов ОС «файл» — это имя цели Trivy вида «<ссылка на образ> (debian 12.x)». Ссылка (тег или digest)
    # при каждом запуске может быть записана по-разному, поэтому в ключ она не входит: иначе одни и те же находки
    # считались бы «исправленными» и «новыми» одновременно.
    where = 'os' if meta.get('origin') == 'os' else finding.file
    return (finding.rule_id, meta.get('package'), meta.get('installed_version'), where)


def _digest(scan):
    return ((scan.scanner_results or {}).get('trivy') or {}).get('digest')


def compare_with_previous(db, scan, findings):
    """Сравнение завершённой проверки образа с предыдущей завершённой проверкой того же образа (None, если сравнивать не с чем)."""
    if scan.kind != 'image' or scan.status != ScanStatus.COMPLETED or not scan.target_url:
        return None
    previous = db.scalar(select(Scan).where(
        Scan.repository_id == scan.repository_id, Scan.kind == 'image', Scan.target_url == scan.target_url,
        Scan.status == ScanStatus.COMPLETED, Scan.id != scan.id,
        tuple_(Scan.created_at, Scan.id) < tuple_(scan.created_at, scan.id)).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(1))
    if previous is None:
        return None
    before = {_key(f) for f in db.scalars(select(Finding).where(Finding.scan_id == previous.id))}
    current = {_key(f): f for f in findings}
    new = [f for key, f in current.items() if key not in before]
    fixed = len(before - set(current))
    now_digest, then_digest = _digest(scan), _digest(previous)
    same = (now_digest == then_digest) if now_digest and then_digest else None
    if same is None:
        text = 'Не удалось сравнить образы по digest: причину новых находок определить нельзя.'
    elif same and new:
        text = 'Образ тот же, но появились новые находки: обновились данные об уязвимостях. Сам образ не менялся.'
    elif same:
        text = 'Образ тот же, новых находок нет.'
    elif new:
        text = 'Образ изменился. Новые находки могут быть из-за изменений в образе или из-за обновления данных об уязвимостях.'
    else:
        text = 'Образ изменился, новых находок нет.'
    new.sort(key=lambda f: (-(f.risk_score or 0), f.rule_id))
    return {'previous_check_id': str(previous.id), 'previous_completed_at': previous.completed_at.isoformat() if previous.completed_at else None,
            'previous_image_digest': then_digest, 'same_image': same, 'new': len(new), 'fixed': fixed, 'unchanged': len(current) - len(new),
            'new_findings': [{'finding_id': str(f.id), 'rule_id': f.rule_id, 'cve': f.cve, 'severity': f.severity.value,
                              'component': (f.extra or {}).get('package'), 'installed_version': (f.extra or {}).get('installed_version')}
                             for f in new[:MAX_LISTED]],
            'new_findings_truncated': len(new) > MAX_LISTED, 'explanation': text}

"""Разбор JSON-отчёта Trivy по Docker-образу.

Только чтение данных: образ не запускается. Любое отклонение от ожидаемого формата
считается ошибкой, а не «чистым» результатом.
"""
import re
from dataclasses import dataclass

from .scanner_catalog import TRIVY_VERSION

SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'}
CLASSES = {'os-pkgs', 'lang-pkgs'}
# Пути внутри образа. Для другого приложения префикс приложения передаётся параметром.
APP_PREFIXES = ('app/',)
TOOLING_PREFIXES = ('usr/local/lib/node_modules/', 'opt/yarn')
OS_REASONS = {
    'fixed': 'исправление есть в обновлённом пакете ОС: обновите базовый образ',
    'affected': 'исправления для пакета ОС пока нет',
    'fix_deferred': 'мейнтейнеры дистрибутива отложили исправление',
    'will_not_fix': 'мейнтейнеры дистрибутива не будут исправлять эту проблему',
}


class ImageReportError(RuntimeError):
    """Отчёт нельзя использовать. Результат проверки не определён."""


@dataclass(frozen=True)
class ImageReport:
    findings: list
    summary: dict


def _text(value, limit=300, required=True):
    if value is None and not required:
        return None
    if not isinstance(value, str) or len(value) > limit or (required and not value) \
            or any(ord(char) < 32 for char in value):
        raise ImageReportError('Некорректное поле в JSON Trivy.')
    return value


def classify(kind, path, app_prefixes=APP_PREFIXES):
    """Откуда пакет: 'os', 'app' (зависимость приложения), 'base-tooling' или 'other'."""
    if kind == 'os-pkgs':
        return 'os'
    path = path or ''
    if path.startswith(tuple(app_prefixes)):
        return 'app'
    if path.startswith(TOOLING_PREFIXES):
        return 'base-tooling'
    return 'other'


def manual_reason(origin, fixed, status):
    """Причина ручного разбора или None, если находку можно пробовать чинить обновлением."""
    if origin == 'app':
        return None if fixed else 'исправленной версии нет'
    if origin == 'base-tooling':
        return 'пакет относится к инструментам базового образа, а не к зависимостям приложения'
    if origin == 'os':
        return OS_REASONS.get(status) or ('статус пакета ОС: ' + (status or 'нет данных'))
    return 'пакет вне приложения и известных инструментов образа'


def parse_image_report(data, app_prefixes=APP_PREFIXES):
    if not isinstance(data, dict) or data.get('SchemaVersion') != 2 or data.get('ArtifactType') != 'container_image':
        raise ImageReportError('Неподдерживаемая схема JSON Trivy для образа.')
    if not isinstance(data.get('Trivy'), dict) or data['Trivy'].get('Version') != TRIVY_VERSION:
        raise ImageReportError('Версия отчёта Trivy не совпадает с установленной политикой.')
    results = data.get('Results')
    if not isinstance(results, list) or not results:
        # Пустой список не доказывает, что образ чист: возможно, Trivy ничего не распознал.
        raise ImageReportError('Trivy не вернул ни одной проверенной цели. Результат не определён.')
    findings, targets = [], []
    for result in results:
        if not isinstance(result, dict) or result.get('Class') not in CLASSES:
            raise ImageReportError('Trivy вернул неподдерживаемый тип результата.')
        targets.append(_text(result.get('Target'), 2048))
        ecosystem = _text(result.get('Type'), 100)
        items = result.get('Vulnerabilities')
        if items is None:
            items = []
        if not isinstance(items, list):
            raise ImageReportError('Некорректный список находок Trivy.')
        for item in items:
            if not isinstance(item, dict):
                raise ImageReportError('Некорректная находка Trivy.')
            severity = _text(item.get('Severity'), 50)
            if severity not in SEVERITIES:
                raise ImageReportError('Неизвестный уровень риска Trivy.')
            rule = _text(item.get('VulnerabilityID'), 64)
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', rule):
                raise ImageReportError('Некорректный идентификатор Trivy.')
            path = _text(item.get('PkgPath'), 2048, required=False)
            fixed = _text(item.get('FixedVersion'), 1000, required=False) or None
            status = _text(item.get('Status'), 32, required=False)
            origin = classify(result['Class'], path, app_prefixes)
            findings.append({
                'category': 'dependency', 'source': 'image', 'origin': origin,
                'file': path or targets[-1], 'rule_id': rule, 'severity': severity, 'ecosystem': ecosystem,
                'package': _text(item.get('PkgName'), 512), 'installed_version': _text(item.get('InstalledVersion'), 300),
                'fixed_version': fixed, 'package_id': _text(item.get('PkgID'), 1000, required=False),
                'cve': rule if re.fullmatch(r'CVE-\d{4}-\d{4,}', rule) else None,
                'fix_status': status, 'manual_reason': manual_reason(origin, fixed, status),
            })
    by_origin = {}
    for finding in findings:
        by_origin[finding['origin']] = by_origin.get(finding['origin'], 0) + 1
    metadata = data.get('Metadata') or {}
    image_id = metadata.get('ImageID')
    digests = metadata.get('RepoDigests')
    summary = {'scanned_targets': targets, 'by_origin': by_origin, 'total': len(findings),
               'fixable_app': sum(1 for f in findings if f['origin'] == 'app' and f['manual_reason'] is None),
               'image_id': image_id if isinstance(image_id, str) else None,
               'repo_digests': [d for d in digests if isinstance(d, str)] if isinstance(digests, list) else []}
    return ImageReport(findings, summary)

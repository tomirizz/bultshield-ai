"""Выбор версии для обновления уязвимой зависимости.

Чистые функции: без сети, базы данных и запуска чужого кода. Список версий реестра
и список устаревших версий передаются снаружи, поэтому логику легко проверять тестами.
"""
import re
from dataclasses import dataclass

_VERSION = re.compile(r'\d+\.\d+\.\d+')
_LOWER_BOUND = re.compile(r'>=\s*(\d+\.\d+\.\d+)')


def parse_version(text):
    """'4.17.21' -> (4, 17, 21). Всё остальное (предрелизы, диапазоны) -> None."""
    text = (text or '').strip()
    return tuple(int(part) for part in text.split('.')) if _VERSION.fullmatch(text) else None


def format_version(version):
    return '.'.join(str(part) for part in version)


def requirement(installed, fixed):
    """Минимальная версия, закрывающая одну находку, либо причина, почему её нет."""
    text = (fixed or '').strip()
    if not text:
        return None, 'исправленной версии нет'
    bound = _LOWER_BOUND.fullmatch(text)
    if bound:
        return parse_version(bound.group(1)), None
    candidates = []
    for part in text.split(','):
        version = parse_version(part)
        if version is None:
            return None, 'формат исправленной версии не поддержан: ' + text[:60]
        candidates.append(version)
    # Сначала ищем исправление в той же мажорной линии: такое обновление безопаснее.
    same_major = [v for v in candidates if v[0] == installed[0] and v > installed]
    if same_major:
        return min(same_major), None
    newer = [v for v in candidates if v > installed]
    if newer:
        return min(newer), None
    return None, 'исправленная версия не новее установленной'


@dataclass(frozen=True)
class UpdatePlan:
    status: str                   # 'PROPOSE' (можно предложить обновление) или 'MANUAL'
    package: str
    installed: str
    target: str | None = None
    major_change: bool = False    # смена мажорной версии: высокий риск поломки
    resolves: tuple = ()          # находки, которые обновление должно закрыть
    manual: tuple = ()            # пары (находка, причина): обновление их не закроет
    reason: str | None = None     # почему весь план ручной


def plan_update(package, installed, findings, available, deprecated=()):
    """findings: список пар (id находки, исправленная версия из Trivy).

    available: все версии пакета из реестра или None, если реестр недоступен.
    deprecated: версии, которые авторы пакета пометили устаревшими.
    """
    current = parse_version(installed)
    if current is None:
        return UpdatePlan('MANUAL', package, installed, reason='не удалось разобрать установленную версию')
    needs, manual = {}, []
    for finding_id, fixed in findings:
        minimum, why = requirement(current, fixed)
        if minimum is None:
            manual.append((finding_id, why))
        else:
            needs[finding_id] = minimum
    if not needs:
        return UpdatePlan('MANUAL', package, installed, manual=tuple(manual),
                          reason='ни одну находку нельзя закрыть обновлением')
    if available is None:
        return UpdatePlan('MANUAL', package, installed, manual=tuple(manual),
                          reason='не удалось получить список версий из реестра; без него нельзя исключить устаревшую версию')
    wanted = max(needs.values())
    blocked = set(deprecated)
    options = sorted(v for v in (parse_version(item) for item in available)
                     if v is not None and v >= wanted and format_version(v) not in blocked)
    if not options:
        return UpdatePlan('MANUAL', package, installed, manual=tuple(manual),
                          reason='нет подходящей версии не ниже ' + format_version(wanted)
                                 + ': все они устарели или отсутствуют в реестре')
    chosen = options[0]
    return UpdatePlan('PROPOSE', package, installed, target=format_version(chosen),
                      major_change=chosen[0] != current[0], resolves=tuple(needs), manual=tuple(manual))

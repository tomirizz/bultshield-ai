"""Оркестратор исправлений: из находок образа получить план обновлений и проверить каждый в песочнице.

Что делает: берёт находки приложения, для каждого пакета выбирает версию (dependency_fix.plan_update по данным
реестра npm), проверяет её в песочнице (sandbox.verify_fix) и присваивает пакету один из статусов ТЗ.
Чего не делает: не меняет проект, не создаёт PR и не вызывает LLM. Пакеты проверяются по одному, каждый
в чистой копии; совместная проверка нескольких обновлений в одном PR остаётся задачей следующего шага.
"""
from dataclasses import dataclass, field

from .dependency_fix import parse_version, plan_update
from .npm_registry import RegistryError, fetch_versions
from .sandbox import (
    BREAKS_APP,
    FIX_VERIFIED,
    INCONCLUSIVE,
    NEW_FINDINGS,
    STILL_DETECTED,
    FixCandidate,
    SandboxConfig,
    verify_fix,
)

# Статусы из ТЗ, которые может присвоить этот модуль. «Обнаружена» и «исправление применено» задаются в других местах.
FIX_PROPOSED = 'fix_proposed'            # исправление предложено, проверка не завершена
FIX_PASSED = 'fix_passed_verification'   # исправление прошло проверку в песочнице (приложение в эксплуатации не исправлено)
MANUAL = 'manual_intervention'           # нужен человек
MAX_PACKAGES = 10

_WHY = {
    STILL_DETECTED: 'после обновления часть находок осталась',
    BREAKS_APP: 'обновление ломает приложение',
    NEW_FINDINGS: 'обновление принесло новые находки',
}


@dataclass
class PackageItem:
    package: str
    installed: str
    finding_ids: list
    status: str
    reason: str
    target: str | None = None
    major_change: bool = False
    needs_review: bool = False
    plan: dict = field(default_factory=dict)
    verification: dict | None = None

    def as_dict(self):
        return dict(self.__dict__)


@dataclass
class AgentResult:
    packages: list
    other: list          # не приложение: ОС, инструменты базового образа и т.п.
    summary: dict

    def as_dict(self):
        return {'packages': [p.as_dict() for p in self.packages], 'other': self.other, 'summary': self.summary}


def _lowest(versions):
    parsed = sorted(v for v in ((parse_version(x), x) for x in versions) if v[0] is not None)
    return parsed[0][1] if parsed else sorted(versions)[0]


def _other_groups(findings):
    groups = {}
    for f in findings:
        if f['origin'] == 'app':
            continue
        key = (f['origin'], f['manual_reason'])
        groups.setdefault(key, set()).add(f['rule_id'] + ' ' + f['package'])
    return [{'origin': origin, 'status': MANUAL, 'reason': reason, 'count': len(items)}
            for (origin, reason), items in sorted(groups.items(), key=lambda kv: (kv[0][0], str(kv[0][1])))]


def run_fix_agent(project_dir, findings, *, registry=fetch_versions, verify=verify_fix, config=None, scan=None,
                  max_packages=MAX_PACKAGES):
    """findings: список находок из parse_image_report. Возвращает AgentResult."""
    config = config or SandboxConfig()
    by_package = {}
    for f in findings:
        if f['origin'] == 'app':
            by_package.setdefault(f['package'], []).append(f)
    items = []
    for number, (package, group) in enumerate(sorted(by_package.items())):
        installed = _lowest({f['installed_version'] for f in group})
        ids = sorted({f['rule_id'] for f in group})
        if number >= max_packages:
            items.append(PackageItem(package, installed, ids, MANUAL,
                                     f'превышен лимит {max_packages} пакетов за одну проверку'))
            continue
        items.append(_handle_package(project_dir, findings, package, installed, group, ids, registry, verify, config, scan))
    return AgentResult(items, _other_groups(findings), _summary(items))


def _handle_package(project_dir, findings, package, installed, group, ids, registry, verify, config, scan):
    pairs = sorted({(f['rule_id'], f['fixed_version'] or '') for f in group})
    try:
        available, deprecated = registry(package)
    except RegistryError as exc:
        available, deprecated = None, ()
        registry_note = str(exc)
    else:
        registry_note = None
    plan = plan_update(package, installed, pairs, available, deprecated)
    described = {'status': plan.status, 'target': plan.target, 'major_change': plan.major_change,
                 'resolves': list(plan.resolves), 'manual': [list(item) for item in plan.manual], 'reason': plan.reason}
    if plan.status != 'PROPOSE':
        reason = plan.reason or 'обновление не предложено'
        if registry_note:
            reason = f'{registry_note} {reason}'
        return PackageItem(package, installed, ids, MANUAL, reason, plan=described)
    kwargs = {'config': config}
    if scan is not None:
        kwargs['scan'] = scan
    result = verify(project_dir, FixCandidate(package, plan.target, resolves=plan.resolves), findings, **kwargs)
    item = PackageItem(package, installed, ids, MANUAL, result.reason, target=plan.target,
                       major_change=plan.major_change, plan=described, verification=result.as_dict())
    if result.outcome == FIX_VERIFIED:
        item.status = FIX_PASSED
        item.needs_review = plan.major_change
        if plan.major_change:
            item.reason += ' Обновление меняет мажорную версию: перед применением нужен просмотр человеком.'
        if plan.manual:
            item.reason += f' Не закрыто обновлением: {len(plan.manual)} (нужен ручной разбор).'
            item.needs_review = True
    elif result.outcome == INCONCLUSIVE:
        item.status = FIX_PROPOSED
        item.reason = 'Исправление предложено, но проверка не завершена: ' + result.reason
    else:
        item.reason = f'{_WHY.get(result.outcome, result.outcome)}: {result.reason}'
    return item


def _summary(items):
    counts = {FIX_PASSED: 0, FIX_PROPOSED: 0, MANUAL: 0}
    for item in items:
        counts[item.status] += 1
    return {'packages': len(items), **counts, 'needs_review': sum(1 for i in items if i.needs_review)}

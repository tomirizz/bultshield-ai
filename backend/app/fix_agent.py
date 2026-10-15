"""Оркестратор исправлений: из находок образа получить план обновлений и проверить каждый в песочнице.

Что делает: берёт находки приложения, для каждого пакета выбирает версию (dependency_fix.plan_update по данным
реестра npm), проверяет её в песочнице (sandbox.verify_fix) и присваивает пакету один из статусов ТЗ.
Чего не делает: не меняет проект и не создаёт PR. Версию может выбрать модель (необязательный planner), но только из набора,
который задал код, и только после проверки в песочнице; без planner или при его сбое используется детерминированный план.
Каждый пакет сначала проверяется
отдельно в чистой копии. Затем все прошедшие проверку и не требующие просмотра обновления проверяются вместе
(одна копия, одна сборка), потому что именно набор из них станет одним PR.
"""
from dataclasses import dataclass, field

from .dependency_fix import candidate_versions, parse_version, plan_update
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
    verify_fixes,
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
    # Выбор версии моделью: что предложено, принято ли, чем закончилась проверка. None, если модель не участвовала.
    llm_plan: dict | None = None
    # Служебные объекты для следующих шагов (PR). В JSON не попадают: файлы могут быть большими.
    candidate: object = field(default=None, repr=False, compare=False)
    result: object = field(default=None, repr=False, compare=False)

    def as_dict(self):
        return {key: value for key, value in self.__dict__.items() if key not in ('candidate', 'result')}


@dataclass
class AgentResult:
    packages: list
    other: list          # не приложение: ОС, инструменты базового образа и т.п.
    summary: dict
    combined: dict | None = None            # итог совместной проверки набора обновлений (None, если набора нет)
    combined_result: object = field(default=None, repr=False, compare=False)

    def as_dict(self):
        return {'packages': [p.as_dict() for p in self.packages], 'other': self.other, 'summary': self.summary,
                'combined': self.combined}


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


def run_fix_agent(project_dir, findings, *, registry=fetch_versions, verify=verify_fix, verify_many=verify_fixes,
                  config=None, scan=None, max_packages=MAX_PACKAGES, combine=True, planner=None):
    """findings: список находок из parse_image_report. Возвращает AgentResult.

    planner(пакет, установленная версия, находки пакета, набор версий, версия по умолчанию) -> словарь выбора модели
    (llm_plan.make_planner) или None, если модель не используется.
    """
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
        items.append(_handle_package(project_dir, findings, package, installed, group, ids, registry, verify, config, scan, planner))
    result = AgentResult(items, _other_groups(findings), _summary(items))
    if combine:
        _combine(result, project_dir, findings, verify_many, config, scan)
    return result


def _combine(result, project_dir, findings, verify_many, config, scan):
    """Проверяет вместе все обновления, прошедшие отдельную проверку и не требующие просмотра человеком."""
    chosen = [i for i in result.packages if i.status == FIX_PASSED and not i.needs_review]
    if not chosen:
        return
    if len(chosen) == 1:
        outcome = chosen[0].result   # отдельная проверка уже совпадает с набором из одного обновления
    else:
        kwargs = {'config': config}
        if scan is not None:
            kwargs['scan'] = scan
        outcome = verify_many(project_dir, [i.candidate for i in chosen], findings, **kwargs)
    result.combined_result = outcome
    result.combined = {'packages': [i.package for i in chosen], **outcome.as_dict()}
    result.summary['combined_outcome'] = outcome.outcome


def _consult(planner, package, installed, group, candidates, default):
    """Выбор версии моделью. None: модель не участвует. Иначе словарь со статусом; сбой выбора не мешает агенту."""
    if planner is None:
        return None
    versions = [c['version'] for c in candidates]
    base = {'candidates': versions, 'default': default}
    if len(candidates) < 2:
        return {**base, 'status': 'SKIPPED', 'message': 'Допустима единственная версия: выбирать не из чего.', 'accepted': None}
    try:
        reply = planner(package, installed, group, candidates, default)
    except Exception:
        # Подробности не сохраняются: в них могут быть пути и тексты ошибок. Агент работает по детерминированному плану.
        return {**base, 'status': 'ERROR', 'message': 'Выбор версии моделью не выполнен: внутренняя ошибка.', 'accepted': None}
    if reply.get('status') == 'NOT_CONFIGURED':
        return None   # модель не подключена: ничего не запрашивалось, в результате нет следов выбора моделью
    return {**base, **reply, 'accepted': None}


def _handle_package(project_dir, findings, package, installed, group, ids, registry, verify, config, scan, planner=None):
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
    candidates = candidate_versions(installed, pairs, available, deprecated, default=plan.target)
    llm = _consult(planner, package, installed, group, candidates, plan.target)
    target = plan.target
    chosen_by_model = bool(llm and llm['status'] == 'COMPLETED' and llm['target'] != plan.target)
    if chosen_by_model:
        target = llm['target']
    result = verify(project_dir, FixCandidate(package, target, resolves=plan.resolves), findings, **kwargs)
    if chosen_by_model and result.outcome in (STILL_DETECTED, BREAKS_APP, NEW_FINDINGS):
        # Версия модели не прошла проверку: проверяем версию детерминированного плана, результат модели сохраняем как отказ.
        llm.update(accepted=False, rejected_outcome=result.outcome, rejected_reason=str(result.reason)[:300])
        target, chosen_by_model = plan.target, False
        result = verify(project_dir, FixCandidate(package, target, resolves=plan.resolves), findings, **kwargs)
    elif llm and llm['status'] == 'COMPLETED':
        llm['accepted'] = True if result.outcome == FIX_VERIFIED else None
    if llm is not None:
        llm['final_target'] = target
    major = parse_version(target)[0] != parse_version(installed)[0]
    candidate = FixCandidate(package, target, resolves=plan.resolves)
    item = PackageItem(package, installed, ids, MANUAL, result.reason, target=target, major_change=major,
                       plan=described, verification=result.as_dict(), candidate=candidate, result=result, llm_plan=llm)
    if result.outcome == FIX_VERIFIED:
        item.status = FIX_PASSED
        item.needs_review = major
        if major:
            item.reason += ' Обновление меняет мажорную версию: перед применением нужен просмотр человеком.'
        if plan.manual:
            item.reason += f' Не закрыто обновлением: {len(plan.manual)} (нужен ручной разбор).'
            item.needs_review = True
        if chosen_by_model:
            item.reason += ' Версию выбрала модель из допустимого набора; выбор проверен в песочнице.'
            if llm.get('needs_review'):
                item.needs_review = True
                item.reason += ' Модель отметила, что нужен просмотр человеком.'
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

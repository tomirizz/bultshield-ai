import json
from pathlib import Path
from types import SimpleNamespace

from app import fix_agent
from app.fix_agent import FIX_PASSED, FIX_PROPOSED, MANUAL, run_fix_agent
from app.image_report import parse_image_report
from app.npm_registry import RegistryError
from app.sandbox import BREAKS_APP, FIX_VERIFIED, INCONCLUSIVE, NEW_FINDINGS, STILL_DETECTED

FIXTURE = Path(__file__).parent / 'fixtures' / 'trivy_image_report.json'
LODASH_VERSIONS = ['4.17.15', '4.17.19', '4.17.20', '4.17.21', '4.17.23', '4.18.0', '4.18.1']


def findings():
    return parse_image_report(json.loads(FIXTURE.read_text())).findings


def registry(versions=LODASH_VERSIONS, deprecated=('4.18.0',)):
    return lambda package: (list(versions), list(deprecated))


class Verifier:
    """Подставляется вместо песочницы: записывает вызовы и возвращает заданный исход."""

    def __init__(self, outcome=FIX_VERIFIED, reason='проверка прошла'):
        self.calls = []
        self.outcome, self.reason = outcome, reason

    def __call__(self, project, candidate, baseline, **kwargs):
        self.calls.append((project, candidate, baseline, kwargs))
        return SimpleNamespace(outcome=self.outcome, reason=self.reason, as_dict=lambda: {'outcome': self.outcome})


def app_finding(package, installed, rule, fixed):
    return {'origin': 'app', 'package': package, 'installed_version': installed, 'rule_id': rule,
            'fixed_version': fixed, 'manual_reason': None if fixed else 'исправленной версии нет'}


def test_lodash_is_planned_skipping_deprecated_release_and_verified():
    verify = Verifier()
    result = run_fix_agent('/p', findings(), registry=registry(), verify=verify)
    (item,) = result.packages
    assert item.package == 'lodash' and item.target == '4.18.1' and item.status == FIX_PASSED
    assert not item.needs_review and item.verification == {'outcome': FIX_VERIFIED}
    ((project, candidate, baseline, kwargs),) = verify.calls
    assert project == '/p' and (candidate.package, candidate.target) == ('lodash', '4.18.1')
    assert len(candidate.resolves) == 7 and len(baseline) == 14


def test_non_app_findings_are_manual_and_never_verified():
    verify = Verifier()
    result = run_fix_agent('/p', findings(), registry=registry(), verify=verify)
    origins = {group['origin'] for group in result.other}
    assert origins == {'os', 'base-tooling'}
    assert all(group['status'] == MANUAL and group['reason'] and group['count'] for group in result.other)
    assert [c[1].package for c in verify.calls] == ['lodash']


def test_without_registry_data_nothing_is_proposed():
    def broken(package):
        raise RegistryError('Реестр npm недоступен: URLError.')
    verify = Verifier()
    item = run_fix_agent('/p', findings(), registry=broken, verify=verify).packages[0]
    assert item.status == MANUAL and 'Реестр npm недоступен' in item.reason and verify.calls == []


def test_finding_without_fixed_version_is_manual():
    verify = Verifier()
    group = [app_finding('request', '2.88.2', 'CVE-2023-28155', None)]
    item = run_fix_agent('/p', group, registry=registry(['2.88.2']), verify=verify).packages[0]
    assert item.status == MANUAL and 'нельзя закрыть обновлением' in item.reason and verify.calls == []


def test_partial_fix_is_flagged_for_review():
    group = [app_finding('qs', '6.5.2', 'CVE-1', '6.5.3'), app_finding('qs', '6.5.2', 'CVE-2', None)]
    verify = Verifier()
    item = run_fix_agent('/p', group, registry=registry(['6.5.2', '6.5.3']), verify=verify).packages[0]
    assert item.status == FIX_PASSED and item.needs_review and 'Не закрыто обновлением: 1' in item.reason
    assert verify.calls[0][1].resolves == ('CVE-1',)


def test_major_version_jump_is_verified_but_needs_review():
    group = [app_finding('uuid', '3.4.0', 'CVE-2026-41907', '11.1.1')]
    verify = Verifier()
    item = run_fix_agent('/p', group, registry=registry(['3.4.0', '11.1.1', '11.1.2'], ()), verify=verify).packages[0]
    assert item.status == FIX_PASSED and item.major_change and item.needs_review
    assert 'мажорную' in item.reason and item.target == '11.1.1'


def test_failed_verification_outcomes_become_manual_with_reason():
    for outcome, text in ((BREAKS_APP, 'ломает приложение'), (STILL_DETECTED, 'часть находок осталась'),
                          (NEW_FINDINGS, 'новые находки')):
        item = run_fix_agent('/p', findings(), registry=registry(), verify=Verifier(outcome, 'причина X')).packages[0]
        assert item.status == MANUAL and text in item.reason and 'причина X' in item.reason


def test_inconclusive_verification_stays_a_proposal():
    item = run_fix_agent('/p', findings(), registry=registry(), verify=Verifier(INCONCLUSIVE, 'нет Docker')).packages[0]
    assert item.status == FIX_PROPOSED and 'проверка не завершена' in item.reason and item.target == '4.18.1'


def test_installed_versions_of_one_package_use_the_lowest():
    group = [app_finding('qs', '6.5.2', 'CVE-1', '6.5.3'), app_finding('qs', '6.10.0', 'CVE-1', '6.5.3, 6.10.3')]
    verify = Verifier()
    item = run_fix_agent('/p', group, registry=registry(['6.5.2', '6.5.3', '6.10.3'], ()), verify=verify).packages[0]
    assert item.installed == '6.5.2'


def test_package_limit_sends_the_rest_to_manual():
    group = [app_finding(f'pkg{n}', '1.0.0', f'CVE-{n}', '1.0.1') for n in range(4)]
    verify = Verifier()
    result = run_fix_agent('/p', group, registry=registry(['1.0.0', '1.0.1'], ()), verify=verify, max_packages=2)
    assert [i.status for i in result.packages] == [FIX_PASSED, FIX_PASSED, MANUAL, MANUAL]
    assert 'лимит' in result.packages[2].reason and len(verify.calls) == 2


def test_summary_counts_and_serialization():
    group = [app_finding('lodash', '4.17.15', 'CVE-1', '4.18.1'), app_finding('request', '2.88.2', 'CVE-2', None)]
    result = run_fix_agent('/p', group, registry=registry(), verify=Verifier())
    assert result.summary == {'packages': 2, FIX_PASSED: 1, FIX_PROPOSED: 0, MANUAL: 1, 'needs_review': 0,
                              'combined_outcome': FIX_VERIFIED}
    json.dumps(result.as_dict())


def test_scan_is_passed_to_the_sandbox_only_when_given():
    verify = Verifier()
    run_fix_agent('/p', findings(), registry=registry(), verify=verify)
    assert 'scan' not in verify.calls[0][3]
    marker = object()
    verify = Verifier()
    run_fix_agent('/p', findings(), registry=registry(), verify=verify, scan=marker)
    assert verify.calls[0][3]['scan'] is marker


def test_module_exposes_statuses_from_the_spec():
    assert {fix_agent.FIX_PASSED, fix_agent.FIX_PROPOSED, fix_agent.MANUAL} == {
        'fix_passed_verification', 'fix_proposed', 'manual_intervention'}


# --- совместная проверка набора обновлений ---

def two_fixable():
    return [app_finding('lodash', '4.17.15', 'CVE-1', '4.18.1'), app_finding('qs', '6.5.2', 'CVE-2', '6.5.3')]


def both_registry(package):
    return (['4.17.15', '4.18.1'] if package == 'lodash' else ['6.5.2', '6.5.3']), []


def test_single_verified_fix_reuses_its_own_result_as_the_set():
    verify, many = Verifier(), Verifier()
    result = run_fix_agent('/p', findings(), registry=registry(), verify=verify, verify_many=many)
    assert many.calls == [] and result.combined['packages'] == ['lodash']
    assert result.combined_result is result.packages[0].result


def test_several_verified_fixes_are_checked_together_once():
    verify, many = Verifier(), Verifier()
    group = two_fixable()
    result = run_fix_agent('/p', group, registry=both_registry, verify=verify, verify_many=many)
    ((project, candidates, baseline, kwargs),) = many.calls
    assert [(c.package, c.target) for c in candidates] == [('lodash', '4.18.1'), ('qs', '6.5.3')]
    assert baseline == group and result.combined['packages'] == ['lodash', 'qs']
    assert result.summary['combined_outcome'] == FIX_VERIFIED


def test_fixes_that_pass_alone_but_fail_together_are_reported_as_such():
    verify, many = Verifier(), Verifier(BREAKS_APP, 'конфликт версий')
    result = run_fix_agent('/p', two_fixable(), registry=both_registry, verify=verify, verify_many=many)
    assert [i.status for i in result.packages] == [FIX_PASSED, FIX_PASSED]
    assert result.summary['combined_outcome'] == BREAKS_APP and result.combined['outcome'] == BREAKS_APP


def test_fixes_needing_review_are_left_out_of_the_set():
    group = [app_finding('uuid', '3.4.0', 'CVE-3', '11.1.1'), app_finding('qs', '6.5.2', 'CVE-2', '6.5.3')]

    def reg(package):
        return (['3.4.0', '11.1.1'] if package == 'uuid' else ['6.5.2', '6.5.3']), []
    many = Verifier()
    result = run_fix_agent('/p', group, registry=reg, verify=Verifier(), verify_many=many)
    assert many.calls == [] and result.combined['packages'] == ['qs']
    assert {i.package: i.needs_review for i in result.packages} == {'qs': False, 'uuid': True}


def test_no_set_when_nothing_passed_or_combining_is_off():
    result = run_fix_agent('/p', findings(), registry=registry(), verify=Verifier(BREAKS_APP), verify_many=Verifier())
    assert result.combined is None and 'combined_outcome' not in result.summary
    off = run_fix_agent('/p', findings(), registry=registry(), verify=Verifier(), combine=False)
    assert off.combined is None


def test_internal_objects_are_not_serialized():
    result = run_fix_agent('/p', findings(), registry=registry(), verify=Verifier(), verify_many=Verifier())
    data = result.as_dict()
    assert 'candidate' not in data['packages'][0] and 'result' not in data['packages'][0]
    assert 'combined_result' not in data
    json.dumps(data)

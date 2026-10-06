from app.dependency_fix import parse_version, plan_update, requirement

# Значения fixed_version взяты из реальных отчётов Trivy по тестовому приложению.
LODASH = [('CVE-2020-8203', '4.17.19'), ('CVE-2021-23337', '4.17.21'), ('CVE-2026-4800', '4.18.0'),
          ('NSWG-ECO-516', '>=4.17.19'), ('CVE-2020-28500', '4.17.21'), ('CVE-2025-13465', '4.17.23'),
          ('CVE-2026-2950', '4.18.0')]
# Список версий для теста придуман, это не копия реестра.
LODASH_VERSIONS = ['4.17.15', '4.17.19', '4.17.20', '4.17.21', '4.17.23', '4.18.0', '4.18.1']


def test_parse_version_accepts_only_plain_versions():
    assert parse_version('4.17.21') == (4, 17, 21)
    assert parse_version('4.0.0-beta.1') is None
    assert parse_version('>=4.17.19') is None
    assert parse_version('') is None
    assert parse_version(None) is None


def test_lodash_skips_deprecated_release_and_picks_next_one():
    plan = plan_update('lodash', '4.17.15', LODASH, LODASH_VERSIONS, deprecated=['4.18.0'])
    assert plan.status == 'PROPOSE'
    assert plan.target == '4.18.1'
    assert not plan.major_change
    assert len(plan.resolves) == 7 and plan.manual == ()


def test_lodash_without_registry_deprecation_data_would_pick_deprecated_version():
    # Показывает, зачем нужен список устаревших версий.
    plan = plan_update('lodash', '4.17.15', LODASH, LODASH_VERSIONS, deprecated=[])
    assert plan.target == '4.18.0'


def test_all_candidates_deprecated_goes_to_manual():
    plan = plan_update('lodash', '4.17.15', LODASH, LODASH_VERSIONS, deprecated=['4.18.0', '4.18.1'])
    assert plan.status == 'MANUAL' and plan.target is None
    assert 'устарели' in plan.reason


def test_no_fixed_version_goes_to_manual_with_reason():
    plan = plan_update('request', '2.88.2', [('CVE-2023-28155', '')], ['2.88.2'])
    assert plan.status == 'MANUAL'
    assert plan.manual == (('CVE-2023-28155', 'исправленной версии нет'),)


def test_same_major_fix_is_preferred_over_major_jump():
    plan = plan_update('form-data', '2.3.3', [('CVE-2025-7783', '2.5.4, 3.0.4, 4.0.4'),
                                              ('CVE-2026-12143', '2.5.6, 3.0.5, 4.0.6')],
                       ['2.3.3', '2.5.4', '2.5.6', '3.0.5', '4.0.6'])
    assert plan.target == '2.5.6'
    assert not plan.major_change


def test_major_jump_is_flagged():
    plan = plan_update('uuid', '3.4.0', [('CVE-2026-41907', '11.1.1, 12.0.1, 13.0.1')],
                       ['3.4.0', '11.1.1', '12.0.1', '13.0.1'])
    assert plan.target == '11.1.1'
    assert plan.major_change


def test_partial_fix_reports_what_stays_open():
    plan = plan_update('pkg', '1.0.0', [('CVE-A', '1.0.5'), ('CVE-B', '')], ['1.0.0', '1.0.5'])
    assert plan.status == 'PROPOSE' and plan.target == '1.0.5'
    assert plan.resolves == ('CVE-A',)
    assert plan.manual == (('CVE-B', 'исправленной версии нет'),)


def test_unsupported_range_is_not_guessed():
    version, reason = requirement((1, 0, 0), '>=1.2.0, <2.0.0')
    assert version is None and 'не поддержан' in reason


def test_registry_unavailable_goes_to_manual():
    plan = plan_update('lodash', '4.17.15', LODASH, None)
    assert plan.status == 'MANUAL'
    assert 'реестра' in plan.reason


def test_prerelease_versions_are_never_chosen():
    plan = plan_update('pkg', '1.0.0', [('CVE-A', '1.0.5')], ['1.0.0', '1.0.5-beta.1', '1.1.0'])
    assert plan.target == '1.1.0'


def test_unparseable_installed_version_goes_to_manual():
    plan = plan_update('pkg', 'latest', [('CVE-A', '1.0.5')], ['1.0.5'])
    assert plan.status == 'MANUAL'

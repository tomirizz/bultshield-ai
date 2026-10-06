import copy
import json
from pathlib import Path

import pytest
from app.dependency_fix import plan_update
from app.image_report import ImageReportError, parse_image_report

FIXTURE = Path(__file__).parent / 'fixtures' / 'trivy_image_report.json'


@pytest.fixture
def report():
    return json.loads(FIXTURE.read_text())


def by_origin(parsed, origin):
    return [f for f in parsed.findings if f['origin'] == origin]


def test_findings_are_split_by_origin(report):
    parsed = parse_image_report(report)
    assert parsed.summary['total'] == 14
    assert parsed.summary['by_origin'] == {'os': 4, 'app': 7, 'base-tooling': 3}
    assert parsed.summary['fixable_app'] == 7
    assert parsed.summary['image_id'].startswith('sha256:')


def test_app_findings_are_lodash_and_fixable(report):
    app = by_origin(parse_image_report(report), 'app')
    assert {f['package'] for f in app} == {'lodash'}
    assert all(f['manual_reason'] is None and f['source'] == 'image' for f in app)
    assert 'NSWG-ECO-516' in {f['rule_id'] for f in app}


def test_cve_field_is_filled_only_for_real_cve_ids(report):
    app = {f['rule_id']: f['cve'] for f in by_origin(parse_image_report(report), 'app')}
    assert app['CVE-2020-8203'] == 'CVE-2020-8203'
    assert app['NSWG-ECO-516'] is None


def test_base_tooling_goes_to_manual(report):
    tooling = by_origin(parse_image_report(report), 'base-tooling')
    assert {f['package'] for f in tooling} == {'brace-expansion'}
    assert all('инструментам базового образа' in f['manual_reason'] for f in tooling)


def test_os_findings_get_reason_from_trivy_status(report):
    reasons = {f['fix_status']: f['manual_reason'] for f in by_origin(parse_image_report(report), 'os')}
    assert set(reasons) == {'affected', 'will_not_fix', 'fix_deferred', 'fixed'}
    assert 'обновите базовый образ' in reasons['fixed']
    assert 'пока нет' in reasons['affected']
    assert all(reasons.values())


def test_app_findings_feed_the_version_planner(report):
    app = by_origin(parse_image_report(report), 'app')
    plan = plan_update('lodash', '4.17.15', [(f['rule_id'], f['fixed_version']) for f in app],
                       ['4.17.15', '4.17.21', '4.18.0', '4.18.1'], deprecated=['4.18.0'])
    assert plan.status == 'PROPOSE' and plan.target == '4.18.1'


def test_custom_app_prefix(report):
    parsed = parse_image_report(report, app_prefixes=('srv/site/',))
    assert parsed.summary['by_origin'].get('app') is None
    assert len(by_origin(parsed, 'other')) == 7


def test_target_without_vulnerabilities_is_clean_but_listed(report):
    for result in report['Results']:
        result['Vulnerabilities'] = None
    parsed = parse_image_report(report)
    assert parsed.findings == []
    assert len(parsed.summary['scanned_targets']) == 2


def test_empty_results_are_not_treated_as_clean(report):
    report['Results'] = []
    with pytest.raises(ImageReportError):
        parse_image_report(report)
    del report['Results']
    with pytest.raises(ImageReportError):
        parse_image_report(report)


@pytest.mark.parametrize('field,value', [('ArtifactType', 'filesystem'), ('SchemaVersion', 1)])
def test_unsupported_schema_is_rejected(report, field, value):
    report[field] = value
    with pytest.raises(ImageReportError):
        parse_image_report(report)


def test_other_trivy_version_is_rejected(report):
    report['Trivy']['Version'] = '0.99.0'
    with pytest.raises(ImageReportError):
        parse_image_report(report)


def test_unknown_severity_is_rejected(report):
    broken = copy.deepcopy(report)
    broken['Results'][1]['Vulnerabilities'][0]['Severity'] = 'SCARY'
    with pytest.raises(ImageReportError):
        parse_image_report(broken)


def test_unsupported_result_class_is_rejected(report):
    report['Results'][0]['Class'] = 'secret'
    with pytest.raises(ImageReportError):
        parse_image_report(report)

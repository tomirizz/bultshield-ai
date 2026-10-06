from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.check_report import STATUS_TEXT, build_report, finding_state
from app.models import (
    Category,
    Finding,
    FindingStatus,
    Scan,
    Scanner,
    ScanStatus,
    Severity,
)
from test_image_pipeline import DIGEST, REFERENCE, normalized


def finding(**changes):
    values = dict(project_id=uuid4(), scan_id=uuid4(), scanner=Scanner.TRIVY, category=Category.DEPENDENCY,
                  title='CVE-2024-1: pkg', description='', severity=Severity.HIGH, rule_id='CVE-2024-1',
                  status=FindingStatus.OPEN, fingerprint='f', file='package-lock.json',
                  extra={'package': 'pkg', 'installed_version': '1.0.0', 'fixed_version': '1.0.5'})
    values.update(changes)
    item = Finding(**values)
    item.id = uuid4()
    return item


def scan(status=ScanStatus.COMPLETED, results=None, kind='static', config=None):
    item = Scan(project_id=uuid4(), repository_id=uuid4(), status=status, kind=kind, scanner_config=config or {},
                scanner_results={'trivy': {'status': 'COMPLETED'}} if results is None else results)
    item.id = uuid4()
    return item


def fix(status='PROPOSED', verification=None, error=None, diff='--- a\n+++ b\n'):
    return SimpleNamespace(id=uuid4(), status=status, verification=verification or {}, error_message=error,
                           description='Объяснение исправления.', diff=diff, timeline=[])


@pytest.mark.parametrize('changes,fix_record,state,reason', [
    ({}, None, 'FOUND', None),
    ({'extra': {'package': 'pkg', 'fixed_version': None}}, None, 'MANUAL_REVIEW', 'исправленной версии нет'),
    ({'extra': {'manual_reason': 'пакет ОС: исправления пока нет'}}, None, 'MANUAL_REVIEW', 'пакет ОС: исправления пока нет'),
    ({'scanner': Scanner.GITLEAKS, 'category': Category.SECRET, 'extra': {}}, None, 'MANUAL_REVIEW', 'не поддерживается'),
    ({'status': FindingStatus.FIX_PROPOSED}, None, 'FIX_PROPOSED', None),
    ({'status': FindingStatus.FIX_APPLIED}, None, 'VERIFYING', None),
    ({'status': FindingStatus.RECHECKING}, None, 'VERIFYING', None),
    ({'status': FindingStatus.VERIFIED_FIXED}, None, 'FIX_VERIFIED', None),
    ({'status': FindingStatus.STILL_DETECTED}, None, 'MANUAL_REVIEW', 'осталась'),
    ({'status': FindingStatus.FIX_PROPOSED}, fix('FAILED', {'outcome': 'INCONCLUSIVE'}, 'Тесты не запустились.'),
     'MANUAL_REVIEW', 'Тесты не запустились.'),
    ({}, fix('FAILED', {}, 'Предложение отклонено при просмотре.'), 'FOUND', None),
])
def test_finding_states(changes, fix_record, state, reason):
    result, why = finding_state(finding(**changes), fix_record)
    assert result == state
    assert (reason is None and why is None) or (reason in why)


def test_deployed_status_is_never_assigned_yet():
    for status in FindingStatus:
        assert finding_state(finding(status=status))[0] != 'FIX_DEPLOYED'
    assert 'FIX_DEPLOYED' in STATUS_TEXT


@pytest.mark.parametrize('status,results,total,expected', [
    (ScanStatus.QUEUED, {}, 0, 'IN_PROGRESS'),
    (ScanStatus.SCANNING, None, 0, 'IN_PROGRESS'),
    (ScanStatus.FAILED, {'trivy': {'status': 'FAILED'}}, 0, 'INCOMPLETE'),
    (ScanStatus.FAILED, None, 5, 'INCOMPLETE'),
    (ScanStatus.COMPLETED, {'gitleaks': {'status': 'COMPLETED'}, 'trivy': {'status': 'FAILED'}}, 3, 'INCOMPLETE'),
    (ScanStatus.COMPLETED, {}, 0, 'INCOMPLETE'),
    (ScanStatus.COMPLETED, None, 0, 'NO_FINDINGS'),
    (ScanStatus.COMPLETED, None, 3, 'FINDINGS'),
])
def test_verdicts_never_turn_failure_into_clean(status, results, total, expected):
    items = [finding() for _ in range(total)]
    report = build_report(scan(status, results), items)
    assert report['verdict']['result'] == expected
    if expected == 'INCOMPLETE':
        assert 'не означает отсутствие уязвимостей' in report['verdict']['statement']
    if expected == 'NO_FINDINGS':
        assert 'не гарантия' in report['verdict']['statement']


def image_report(**kwargs):
    findings = normalized()
    for item in findings:
        item.id = uuid4()
    config = {'image': {'reference': REFERENCE}}
    record = scan(kind='image', config=config, results={'trivy': {'status': 'COMPLETED', 'digest': DIGEST}})
    return build_report(record, findings, **kwargs)


def test_image_report_sections_and_counts():
    report = image_report()
    assert report['subject']['image'] == REFERENCE and report['subject']['image_digest'] == DIGEST
    assert report['facts']['by_status'] == {'FOUND': 7, 'MANUAL_REVIEW': 7}
    assert report['facts']['by_origin'] == {'os': 4, 'app': 7, 'base-tooling': 3}
    assert report['facts']['total_findings'] == 14 and report['findings']['total'] == 14
    kinds = sorted(a['action'] for a in report['proposed_actions'])
    assert kinds == ['manual_review'] * 7 + ['update_dependency'] * 7
    assert report['assumptions'] == []
    assert any('не реализована' in text for text in report['limitations'])
    assert 'FIX_DEPLOYED' not in report['facts']['by_status']


def test_report_item_has_the_unified_fields():
    item = image_report()['findings']['items'][0]
    for key in ('title', 'severity', 'component', 'scanner', 'source', 'status', 'status_text', 'fixed_version', 'manual_reason'):
        assert key in item
    assert item['source'] == 'image'


def test_pagination_changes_items_not_totals():
    page = image_report(limit=5, offset=10)
    assert len(page['findings']['items']) == 4 and page['findings']['total'] == 14
    assert page['facts']['by_status'] == {'FOUND': 7, 'MANUAL_REVIEW': 7}


def test_verified_fix_is_not_reported_as_deployed():
    item = finding(status=FindingStatus.VERIFIED_FIXED)
    record = fix('VERIFIED_FIXED', {'outcome': 'VERIFIED_FIXED', 'scope': 'isolated_copy'})
    report = build_report(scan(), [item], fixes={item.id: record})
    shown = report['findings']['items'][0]
    assert shown['status'] == 'FIX_VERIFIED'
    assert shown['fix']['applied_to_running_app'] is False and shown['fix']['scope'] == 'isolated_copy'
    assert shown['fix']['diff'] == record.diff
    assert [a['action'] for a in report['proposed_actions']] == ['apply_after_review']
    assert 'FIX_DEPLOYED' not in report['facts']['by_status']


def test_ai_text_goes_to_assumptions_only():
    item = finding()
    analysis = SimpleNamespace(model='qwen', explanation='AI_TEXT_MARKER', recommended_fix='обновить пакет')
    report = build_report(scan(), [item], analyses={item.id: analysis})
    assert [a['source'] for a in report['assumptions']] == ['ai_analysis']
    assert 'AI_TEXT_MARKER' not in str(report['facts']) and 'AI_TEXT_MARKER' not in str(report['verdict'])

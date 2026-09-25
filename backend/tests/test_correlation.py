import json
from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from app import ai_service as ai
from app import correlation as corr
from app.models import AIAnalysis, CorrelationRun, Finding
from test_security_dashboard import finding, project, scan


@pytest.fixture
def enabled(monkeypatch):
    settings = SimpleNamespace(ai_enabled=True, ai_model='test', ai_timeout_seconds=10)
    monkeypatch.setattr(corr, 'get_settings', lambda: settings)
    monkeypatch.setattr(ai, 'get_settings', lambda: settings)
    return settings


def proposal(refs=None):
    return {'groups': [{'title': 'Общая зависимость', 'finding_refs': refs or ['F1', 'F2'],
                        'interpretation': 'Возможна общая причина в настройке зависимостей.',
                        'verification': 'Проверьте исходные данные и контекст вручную.'}]}


def setup(client, db, count=2):
    p = project(client)
    s = scan(db, p)
    findings = [finding(db, s) for _ in range(count)]
    db.commit()
    return p, findings, f"/api/projects/{p['id']}/correlation"


def test_groups_persist_with_original_evidence_and_idempotency(client, db, enabled, monkeypatch):
    p, findings, path = setup(client, db)
    other = project(client, 'Other')
    finding(db, scan(db, other))
    db.commit()
    first = client.post(path)
    assert first.status_code == 202
    assert client.post(path).json()['id'] == first.json()['id']
    captured = []
    def infer(payload, **kwargs):
        captured.append(payload)
        return proposal()
    monkeypatch.setattr(ai, 'infer', infer)
    assert corr.process_next()
    completed = client.get(path).json()
    assert completed['status'] == 'COMPLETED'
    evidence = completed['groups'][0]['scanner_evidence']
    assert {f['id'] for f in evidence} == {str(f.id) for f in findings}
    assert all(f['project_id'] == p['id'] for f in evidence)
    assert len(captured[0]['findings']) == 2
    assert client.post(path).json()['id'] == first.json()['id']
    assert all(db.get(Finding, f.id).status.value == 'OPEN' for f in findings)
    newer = scan(db, p, 1)
    finding(db, newer)
    finding(db, newer)
    db.commit()
    assert client.get(path).json()['stale']
    assert client.post(path).json()['id'] != first.json()['id']


@pytest.mark.parametrize('refs', [['F1', 'F1'], ['F1', 'F99'], ['F1', str(uuid4())]])
def test_invalid_references_rejected(refs):
    with pytest.raises(ValueError):
        corr.validate_groups(proposal(refs), ['a', 'b'])


def test_overlapping_groups_rejected_and_empty_allowed():
    output = proposal()
    output['groups'] *= 2
    with pytest.raises(ValueError):
        corr.validate_groups(output, ['a', 'b'])
    assert corr.validate_groups({'groups': []}, ['a', 'b']) == []


def test_payload_redacts_untrusted_content_preserves_aliases(client, db):
    _, findings, _ = setup(client, db)
    secret = 'ghp_' + 'A' * 36
    for f in findings:
        f.title = f.description = f.file = f.evidence = secret
        f.extra = {'package': secret}
    payload = corr.payload_for(findings)
    assert secret not in json.dumps(payload)
    a, b = payload['findings']
    assert a['file_ref'] == b['file_ref'] and a['package_ref'] == b['package_ref']


def test_invalid_output_fails_atomically_and_retryable(client, db, enabled, monkeypatch):
    _, _, path = setup(client, db)
    first = client.post(path).json()
    monkeypatch.setattr(ai, 'infer', lambda *a, **kw: proposal(['F1', 'F99']))
    assert corr.process_next()
    failed = client.get(path).json()
    assert failed['status'] == 'FAILED' and failed['groups'] == []
    assert client.post(path).json()['id'] != first['id']


def test_capacity_scope_and_disabled(client, db, enabled):
    _, _, path = setup(client, db, 14)
    queued = client.post(path).json()
    assert queued['total_findings'] == 14 and queued['analysed_findings'] == 12
    enabled.ai_enabled = False
    assert client.post(path).status_code == 503
    enabled.ai_enabled = True
    assert client.post(f'/api/projects/{uuid4()}/correlation').status_code == 404
    p = project(client, 'Empty')
    assert client.post(f"/api/projects/{p['id']}/correlation").status_code == 409


def test_shared_worker_exclusion_and_recovery(client, db, enabled, monkeypatch):
    _, findings, path = setup(client, db)
    queued = client.post(path).json()
    ai_run = AIAnalysis(finding_id=findings[0].id, model='test', status='RUNNING', started_at=ai.now())
    db.add(ai_run)
    db.commit()
    assert corr.process_next() is False
    ai_run.status = 'COMPLETED'
    run = db.get(CorrelationRun, UUID(queued['id']))
    run.status, run.started_at = 'RUNNING', ai.now()
    db.commit()
    assert ai.process_next() is False
    run.started_at = ai.now() - timedelta(minutes=5)
    db.commit()
    assert client.get(path).json()['status'] == 'FAILED'
    assert client.post(path).json()['status'] == 'PENDING'

from uuid import uuid4

import pytest
from app import image_pipeline, worker
from test_gitleaks import worker_db as worker_db
from test_image_jobs import DIGEST, REFERENCE, repository, scan_result


@pytest.fixture(autouse=True)
def allow_local_registry(monkeypatch):
    monkeypatch.setenv('IMAGE_ALLOWED_REGISTRIES', 'localhost:5001')


def test_image_check_is_queued_and_idempotent(client):
    repo = str(repository(client))
    first = client.post('/api/checks', json={'repository_id': repo, 'image': REFERENCE})
    assert first.status_code == 202
    body = first.json()
    assert body['kind'] == 'image' and body['status'] == 'QUEUED'
    assert body['scanner_config']['image']['reference'] == REFERENCE
    again = client.post('/api/checks', json={'repository_id': repo, 'image': REFERENCE}).json()
    assert again['id'] == body['id']
    fetched = client.get(f"/api/checks/{body['id']}")
    assert fetched.status_code == 200 and fetched.json()['id'] == body['id']
    assert len(client.get('/api/scans').json()) == 1


def test_repository_check_is_a_source_scan(client):
    body = client.post('/api/checks', json={'repository_id': str(repository(client))}).json()
    assert body['kind'] == 'static' and body['status'] == 'QUEUED'


@pytest.mark.parametrize('payload,status', [
    ({'image': ''}, 422),
    ({'image': 'evil.example.com/app:main'}, 422),
    ({'commit': 'a' * 40}, 422),
    ({'image': 'x' * 300}, 422),
    ({'repository_id': 'not-a-uuid', 'image': REFERENCE}, 422),
    ({'repository_id': str(uuid4()), 'image': REFERENCE}, 404),
])
def test_invalid_requests_are_rejected(client, payload, status):
    body = {'repository_id': str(repository(client)), **payload}
    assert client.post('/api/checks', json=body).status_code == status, payload


def test_missing_repository_id_and_unknown_check(client):
    assert client.post('/api/checks', json={'image': REFERENCE}).status_code == 422
    assert client.get(f'/api/checks/{uuid4()}').status_code == 404
    assert client.get('/api/checks/not-a-uuid').status_code == 422


def test_full_cycle_over_http(client, worker_db, monkeypatch):
    check = client.post('/api/checks', json={'repository_id': str(repository(client)), 'image': REFERENCE}).json()
    monkeypatch.setattr(image_pipeline, 'run_image_scan', lambda reference: scan_result())
    worker.process_job(worker.claim_job())
    done = client.get(f"/api/checks/{check['id']}").json()
    assert done['status'] == 'COMPLETED' and done['scanner_results']['trivy']['digest'] == DIGEST
    assert len(client.get('/api/findings', params={'scan_id': check['id']}).json()) == 14

from contextlib import contextmanager
from uuid import UUID, uuid4

import pytest
from app import image_pipeline, scan_engine, worker
from app.models import Finding, Scan
from app.repository_checkout import RepositoryCheckoutError
from sqlalchemy import func, select
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


def test_configuration_exposes_capabilities_without_secrets(client):
    response = client.get('/api/checks-configuration')
    assert response.status_code == 200
    data = response.json()
    assert data['image_registries'] == ['localhost:5001']
    assert data['runtime_deployment_observed'] is False
    assert data['sandbox_available_in_web'] is False
    assert not any('token' in key or 'endpoint' in key or 'password' in key for key in data)


def test_repository_check_is_a_source_scan(client):
    body = client.post('/api/checks', json={'repository_id': str(repository(client))}).json()
    assert body['kind'] == 'static' and body['status'] == 'QUEUED'


@pytest.mark.parametrize('payload,status', [
    ({'image': ''}, 422),
    ({'image': 'evil.example.com/app:main'}, 422),
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


SHA = 'a1b2c3d4e5' * 4


def make_repository(client, name):
    project = client.post('/api/projects', json={
        'name': name, 'repository': {'url': f'https://github.com/example/{name}', 'default_branch': 'main'}}).json()
    return project['id'], project['repositories'][0]['id']


def test_commit_check_is_a_pinned_source_scan(client):
    repo = str(repository(client))
    response = client.post('/api/checks', json={'repository_id': repo, 'commit': SHA})
    assert response.status_code == 202
    body = response.json()
    assert body['kind'] == 'static' and body['status'] == 'QUEUED'
    assert body['scanner_config']['requested_commit'] == SHA and body['scanner_config']['trigger'] == 'api'
    report = client.get(f"/api/checks/{body['id']}/report").json()
    assert report['subject']['requested_commit'] == SHA and report['subject']['commit_sha'] is None


def test_check_without_commit_is_not_pinned(client):
    first = client.post('/api/checks', json={'repository_id': str(repository(client)), 'commit': None}).json()
    assert first['kind'] == 'static' and 'requested_commit' not in first['scanner_config']
    _, other = make_repository(client, 'other')
    second = client.post('/api/checks', json={'repository_id': other}).json()
    assert 'requested_commit' not in second['scanner_config']


def test_same_commit_is_idempotent_and_others_are_refused_while_active(client):
    repo = str(repository(client))
    first = client.post('/api/checks', json={'repository_id': repo, 'commit': SHA}).json()
    again = client.post('/api/checks', json={'repository_id': repo, 'commit': SHA})
    assert again.status_code == 202 and again.json()['id'] == first['id']
    assert client.post('/api/checks', json={'repository_id': repo, 'commit': 'b' * 40}).status_code == 409
    assert client.post('/api/checks', json={'repository_id': repo}).status_code == 409
    assert len(client.get('/api/scans').json()) == 1


def test_plain_check_does_not_return_a_pinned_scan(client):
    repo = str(repository(client))
    client.post('/api/checks', json={'repository_id': repo})
    assert client.post('/api/checks', json={'repository_id': repo, 'commit': SHA}).status_code == 409


@pytest.mark.parametrize('commit', ['abc1234', 'A' * 40, 'a' * 39, 'a' * 41, 'main', '', ' ', 'g' * 40, 123, ['a' * 40]])
def test_invalid_commit_is_rejected_and_nothing_is_queued(client, commit):
    repo = str(repository(client))
    assert client.post('/api/checks', json={'repository_id': repo, 'commit': commit}).status_code == 422
    assert client.get('/api/scans').json() == []


def test_commit_and_image_together_are_rejected(client):
    repo = str(repository(client))
    response = client.post('/api/checks', json={'repository_id': repo, 'image': REFERENCE, 'commit': SHA})
    assert response.status_code == 422 and 'image' in response.json()['detail'] and 'commit' in response.json()['detail']
    assert client.get('/api/scans').json() == []


def test_commit_not_accepted_as_query_parameter_of_plain_scan_route(client):
    repo = str(repository(client))
    body = client.post(f'/api/scans?commit={SHA}', json={'repository_id': repo}).json()
    assert 'requested_commit' not in body['scanner_config']


def test_commit_check_skips_the_companion_web_scan(client, db, monkeypatch):
    monkeypatch.setenv('NUCLEI_ALLOWED_TARGETS', 'https://stage.example')
    plain_project, plain_repo = make_repository(client, 'plain')
    pinned_project, pinned_repo = make_repository(client, 'pinned')
    for project in (plain_project, pinned_project):
        target = client.post(f'/api/projects/{project}/targets', json={'url': 'https://stage.example/', 'confirmed_control': True})
        assert target.status_code == 201
    client.post('/api/checks', json={'repository_id': plain_repo})
    assert db.scalar(select(func.count()).select_from(Scan).where(Scan.project_id == UUID(plain_project))) == 2
    client.post('/api/checks', json={'repository_id': pinned_repo, 'commit': SHA})
    kinds = db.scalars(select(Scan.kind).where(Scan.project_id == UUID(pinned_project))).all()
    assert kinds == ['static']


def test_worker_checks_out_exactly_the_requested_commit(client, worker_db, monkeypatch, tmp_path):
    repo = str(repository(client))
    check = client.post('/api/checks', json={'repository_id': repo, 'commit': SHA}).json()
    seen = []

    @contextmanager
    def checkout(url, branch, commit=None):
        seen.append((url, branch, commit))
        yield tmp_path, commit

    monkeypatch.setattr(scan_engine, 'checkout_repository', checkout)
    monkeypatch.setattr(scan_engine, 'run_gitleaks', lambda path: [])
    worker.process_job(worker.claim_job())
    assert seen == [('https://github.com/example/demo', 'main', SHA)]
    done = client.get(f"/api/checks/{check['id']}").json()
    assert done['status'] == 'COMPLETED' and done['commit_sha'] == SHA
    report = client.get(f"/api/checks/{check['id']}/report").json()
    assert report['subject']['commit_sha'] == SHA == report['subject']['requested_commit']
    # После завершения тот же коммит можно проверить снова: это новая проверка, а не повтор старой.
    again = client.post('/api/checks', json={'repository_id': repo, 'commit': SHA})
    assert again.status_code == 202 and again.json()['id'] != check['id']


def test_unavailable_commit_fails_and_never_looks_clean(client, db, worker_db, monkeypatch):
    check = client.post('/api/checks', json={'repository_id': str(repository(client)), 'commit': SHA}).json()

    @contextmanager
    def unavailable(url, branch, commit=None):
        raise RepositoryCheckoutError('Commit исходной проверки недоступен.')
        yield

    monkeypatch.setattr(scan_engine, 'checkout_repository', unavailable)
    worker.process_job(worker.claim_job())
    done = client.get(f"/api/checks/{check['id']}").json()
    assert done['status'] == 'FAILED' and done['error_message'] == 'Commit исходной проверки недоступен.'
    assert db.scalar(select(func.count()).select_from(Finding)) == 0
    report = client.get(f"/api/checks/{check['id']}/report").json()
    assert report['check']['status'] == 'FAILED' and report['verdict']['result'] != 'CLEAN'
    assert report['subject']['requested_commit'] == SHA and report['subject']['commit_sha'] is None

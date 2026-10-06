from uuid import uuid4

import pytest
from app import image_pipeline, worker
from app.image_scan import ImageScanError
from test_gitleaks import worker_db as worker_db
from test_image_jobs import DIGEST, REFERENCE, repository, scan_result


@pytest.fixture(autouse=True)
def allow_local_registry(monkeypatch):
    monkeypatch.setenv('IMAGE_ALLOWED_REGISTRIES', 'localhost:5001')


def queue(client):
    return client.post('/api/checks', json={'repository_id': str(repository(client)), 'image': REFERENCE}).json()


def test_report_after_a_full_image_check(client, worker_db, monkeypatch):
    check = queue(client)
    assert client.get(f"/api/checks/{check['id']}/report").json()['verdict']['result'] == 'IN_PROGRESS'
    monkeypatch.setattr(image_pipeline, 'run_image_scan', lambda reference: scan_result())
    worker.process_job(worker.claim_job())
    report = client.get(f"/api/checks/{check['id']}/report").json()
    assert report['verdict']['result'] == 'FINDINGS'
    assert report['facts']['by_status'] == {'FOUND': 7, 'MANUAL_REVIEW': 7}
    assert report['subject']['image_digest'] == DIGEST
    assert report['findings']['total'] == 14 and report['findings']['items'][0]['risk_score'] is not None
    short = client.get(f"/api/checks/{check['id']}/report", params={'limit': 5}).json()
    assert len(short['findings']['items']) == 5 and short['findings']['total'] == 14


def test_report_of_a_failed_scan_is_incomplete(client, worker_db, monkeypatch):
    check = queue(client)

    def fail(reference):
        raise ImageScanError('Trivy завершился с ошибкой (1); проверка неполная.')
    monkeypatch.setattr(image_pipeline, 'run_image_scan', fail)
    worker.process_job(worker.claim_job())
    report = client.get(f"/api/checks/{check['id']}/report").json()
    assert report['verdict']['result'] == 'INCOMPLETE' and report['findings']['total'] == 0
    assert report['check']['error_code'] == 'SCANNER_FAILED'


def test_report_validation(client):
    check = queue(client)
    assert client.get(f'/api/checks/{uuid4()}/report').status_code == 404
    for params in ({'limit': 0}, {'limit': 501}, {'offset': -1}):
        assert client.get(f"/api/checks/{check['id']}/report", params=params).status_code == 422

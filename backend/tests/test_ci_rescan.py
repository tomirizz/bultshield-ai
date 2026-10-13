import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import uvicorn
from app import image_jobs, image_pipeline, image_rescan, worker
from app.config import Settings, get_settings
from app.image_history import compare_with_previous
from app.image_jobs import create_image_scan
from app.image_scan import ImageScanError, ImageScanResult
from app.main import create_app
from app.models import AuditEvent, Project, Repository, Scan, ScanJob, ScanStatus, User
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from test_gitleaks import worker_db as worker_db  # noqa: F401
from test_image_jobs import DIGEST, REFERENCE, repository, scan_result
from test_image_jobs import allow_local_registry as allow_local_registry

OTHER = 'localhost:5001/other-app:main'
DIGEST2 = 'sha256:' + 'b' * 64
TOKEN = 'ci-token-' + 'x' * 40
SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
BACKEND = Path(__file__).resolve().parents[1]


def finish(db, repo_id, reference=REFERENCE, *, digest=DIGEST, drop=0, fail=False, monkeypatch=None, **options):
    """Создаёт проверку образа и доводит её через worker до конца (успех, сбой сканера или без части находок)."""
    scan = create_image_scan(db, repo_id, reference, **options)

    def run(ref):
        if fail:
            raise ImageScanError('Trivy завершился с ошибкой (1); проверка неполная.')
        base = scan_result()
        findings = base.report.findings[:len(base.report.findings) - drop] if drop else base.report.findings
        return ImageScanResult(ref, digest, base.platform, base.db_updated_at, replace(base.report, findings=findings))
    monkeypatch.setattr(image_pipeline, 'run_image_scan', run)
    worker.process_job(worker.claim_job())
    db.expire_all()
    return db.get(Scan, scan.id)


def age(db, hours):
    """Делает все проверки старше на указанное число часов."""
    db.execute(text('UPDATE scans SET created_at = created_at - make_interval(hours => :h), '
                    'completed_at = completed_at - make_interval(hours => :h)'), {'h': hours})
    db.commit()


# ---- запуск проверки: watch и trigger ----

def test_image_check_records_watch_and_trigger(client, db):
    repo = str(repository(client))
    default = client.post('/api/checks', json={'repository_id': repo, 'image': REFERENCE}).json()
    assert default['scanner_config']['watch'] is False and default['scanner_config']['trigger'] == 'api'
    db.execute(text("UPDATE scan_jobs SET status = 'COMPLETED'"))
    db.execute(text("UPDATE scans SET status = 'COMPLETED'"))
    db.commit()
    ci = client.post('/api/checks', json={'repository_id': repo, 'image': OTHER, 'watch': True, 'trigger': 'ci'}).json()
    assert ci['scanner_config']['watch'] is True and ci['scanner_config']['trigger'] == 'ci'
    report = client.get(f"/api/checks/{ci['id']}/report").json()
    assert report['subject']['trigger'] == 'ci' and report['subject']['watched'] is True


def test_watch_needs_an_image_and_trigger_is_limited(client):
    repo = str(repository(client))
    assert client.post('/api/checks', json={'repository_id': repo, 'watch': True}).status_code == 422
    assert client.post('/api/checks', json={'repository_id': repo, 'commit': 'a' * 40, 'watch': True}).status_code == 422
    assert client.post('/api/checks', json={'repository_id': repo, 'image': REFERENCE, 'trigger': 'schedule'}).status_code == 422
    assert client.post('/api/checks', json={'repository_id': repo, 'image': REFERENCE, 'watch': 'maybe'}).status_code == 422


def test_commit_check_can_carry_the_ci_label(client):
    repo = str(repository(client))
    body = client.post('/api/checks', json={'repository_id': repo, 'commit': 'a' * 40, 'trigger': 'ci'}).json()
    assert body['scanner_config']['trigger'] == 'ci' and body['scanner_config']['requested_commit'] == 'a' * 40


def test_repeated_request_updates_watch_on_the_active_check(client):
    repo = str(repository(client))
    first = client.post('/api/checks', json={'repository_id': repo, 'image': REFERENCE}).json()
    second = client.post('/api/checks', json={'repository_id': repo, 'image': REFERENCE, 'watch': True}).json()
    assert second['id'] == first['id'] and second['scanner_config']['watch'] is True
    third = client.post('/api/checks', json={'repository_id': repo, 'image': REFERENCE, 'watch': False}).json()
    assert third['id'] == first['id'] and third['scanner_config']['watch'] is False


# ---- токен CI ----

@pytest.fixture
def two_owners(db, monkeypatch):
    users = [User(display_name='owner'), User(display_name='stranger')]
    db.add_all(users)
    db.flush()
    projects = [Project(owner_id=u.id, name=f'project {i}') for i, u in enumerate(users)]
    db.add_all(projects)
    db.flush()
    repos = [Repository(project_id=p.id, url=f'https://github.com/example/demo{i}', default_branch='main') for i, p in enumerate(projects)]
    db.add_all(repos)
    db.commit()
    settings = get_settings()
    monkeypatch.setattr(settings, 'auth_enabled', True)
    monkeypatch.setattr(settings, 'ci_trigger_token', SecretStr(TOKEN))
    monkeypatch.setattr(settings, 'ci_trigger_owner_id', str(users[0].id))
    return users, repos


def api(**kw):
    return TestClient(create_app(), base_url=get_settings().public_url, **kw)


def bearer(token=TOKEN):
    return {'Authorization': f'Bearer {token}'}


def test_valid_token_can_start_and_read_checks(two_owners, db):
    users, repos = two_owners
    with api() as client:
        response = client.post('/api/checks', headers=bearer(), json={'repository_id': str(repos[0].id), 'image': REFERENCE, 'trigger': 'ci'})
        assert response.status_code == 202
        check = response.json()['id']
        assert client.get(f'/api/checks/{check}', headers=bearer()).status_code == 200
        report = client.get(f'/api/checks/{check}/report', headers=bearer())
        assert report.status_code == 200 and report.json()['subject']['trigger'] == 'ci'
    events = db.scalars(select(AuditEvent).where(AuditEvent.action == 'POST /api/checks')).all()
    assert events and events[0].user_id == users[0].id and events[0].outcome == '202'


def test_token_acts_only_as_its_owner(two_owners, db):
    users, repos = two_owners
    strangers = Scan(project_id=repos[1].project_id, repository_id=repos[1].id, kind='image', target_url='localhost:5001/x')
    db.add(strangers)
    db.commit()
    with api() as client:
        assert client.post('/api/checks', headers=bearer(), json={'repository_id': str(repos[1].id), 'image': REFERENCE}).status_code == 404
        assert client.get(f'/api/checks/{strangers.id}', headers=bearer()).status_code == 404
        assert client.get(f'/api/checks/{strangers.id}/report', headers=bearer()).status_code == 404
        own = client.post('/api/checks', headers=bearer(), json={'repository_id': str(repos[0].id), 'image': REFERENCE})
        assert own.status_code == 202


@pytest.mark.parametrize('method, path', [
    ('GET', '/api/projects'), ('GET', '/api/findings'), ('GET', '/api/audit-log'), ('GET', '/api/checks'), ('POST', '/api/scans'),
    ('POST', '/api/projects'), ('GET', '/api/checks/00000000-0000-4000-8000-000000000000/extra'),
    ('GET', '/api/checks/00000000-0000-4000-8000-000000000000/report/'), ('POST', '/api/checks/00000000-0000-4000-8000-000000000000'),
    ('GET', '/api/checks/not-a-uuid'), ('DELETE', '/api/checks/00000000-0000-4000-8000-000000000000'),
    ('PUT', '/api/checks'), ('GET', '/api/auth/status/../../projects'),
    ('POST', '/api/checks/00000000-0000-4000-8000-000000000000/explanations'),
    ('GET', '/api/checks/00000000-0000-4000-8000-000000000000/explanations'),
])
def test_token_is_refused_everywhere_else(two_owners, method, path):
    with api() as client:
        response = client.request(method, path, headers=bearer(), json={} if method in ('POST', 'PUT') else None)
        if path.startswith('/api/auth'):
            assert response.status_code in (401, 403, 404)
        else:
            assert response.status_code == 403 and 'только запуск и чтение проверок' in response.json()['detail']


@pytest.mark.parametrize('headers', [
    {}, {'Authorization': 'Bearer wrong-token-' + 'y' * 40}, {'Authorization': TOKEN}, {'Authorization': 'Basic ' + TOKEN},
    {'Authorization': 'Bearer '}, {'Authorization': 'Bearer ' + TOKEN + 'x'}, {'Authorization': 'Bearer ' + 'z' * 600},
])
def test_wrong_or_missing_token_is_just_unauthenticated(two_owners, headers):
    _, repos = two_owners
    with api() as client:
        response = client.post('/api/checks', headers=headers, json={'repository_id': str(repos[0].id), 'image': REFERENCE})
        assert response.status_code == 401 and TOKEN not in response.text


def test_scheme_name_is_case_insensitive(two_owners):
    _, repos = two_owners
    with api() as client:
        response = client.post('/api/checks', headers={'Authorization': f'bearer {TOKEN}'}, json={'repository_id': str(repos[0].id), 'image': REFERENCE})
        assert response.status_code == 202


def test_disabled_token_is_never_accepted(two_owners, monkeypatch):
    _, repos = two_owners
    monkeypatch.setattr(get_settings(), 'ci_trigger_token', SecretStr(''))
    with api() as client:
        for token in (TOKEN, '', 'x'):
            response = client.post('/api/checks', headers=bearer(token), json={'repository_id': str(repos[0].id), 'image': REFERENCE})
            assert response.status_code == 401


def test_token_does_not_bypass_when_auth_is_off(client):
    # Без обязательного входа токен ничего не меняет: запросы и так идут как в демо-режиме.
    repo = str(repository(client))
    assert client.post('/api/checks', headers=bearer(), json={'repository_id': repo, 'image': REFERENCE}).status_code == 202


def test_ci_settings_are_validated():
    base = {'database_url': 'postgresql://u:p@localhost/db'}
    assert Settings(**base).ci_trigger_token.get_secret_value() == ''
    ok = Settings(**base, ci_trigger_token=TOKEN, ci_trigger_owner_id=str(uuid.uuid4()))
    assert TOKEN not in repr(ok) and TOKEN not in ok.model_dump_json()
    for bad in ({'ci_trigger_token': 'short', 'ci_trigger_owner_id': str(uuid.uuid4())},
                {'ci_trigger_token': TOKEN},
                {'ci_trigger_token': TOKEN, 'ci_trigger_owner_id': 'not-a-uuid'}):
        with pytest.raises(ValueError):
            Settings(**base, **bad)
    with pytest.raises(ValueError):
        Settings(**base, image_rescan_hours=-1)


# ---- перепроверка по расписанию ----

def test_only_the_latest_watched_check_of_each_image_counts(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, REFERENCE, watch=True, monkeypatch=monkeypatch)
    finish(db, repo, OTHER, watch=True, monkeypatch=monkeypatch)
    assert {s.scanner_config['image']['reference'] for s in image_rescan.watched_images(db)} == {REFERENCE, OTHER}
    finish(db, repo, OTHER, watch=False, monkeypatch=monkeypatch)  # слежение за образом снято
    assert [s.scanner_config['image']['reference'] for s in image_rescan.watched_images(db)] == [REFERENCE]


def test_unwatched_and_unfinished_checks_are_not_watched(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, REFERENCE, monkeypatch=monkeypatch)
    assert image_rescan.watched_images(db) == []
    create_image_scan(db, repo, OTHER, watch=True)  # ещё в очереди
    assert image_rescan.watched_images(db) == []


def test_due_image_is_rescanned_with_the_schedule_label(client, db, worker_db, monkeypatch):
    repo = repository(client)
    first = finish(db, repo, REFERENCE, watch=True, trigger='ci', monkeypatch=monkeypatch)
    assert image_rescan.rescan_due(db, timedelta(hours=24)) == []  # срок ещё не вышел
    created = image_rescan.rescan_due(db, timedelta(hours=24), now=datetime.now(UTC) + timedelta(hours=25))
    assert len(created) == 1
    new = created[0]
    config = new.scanner_config
    assert new.kind == 'image' and new.status == ScanStatus.QUEUED and config['trigger'] == 'schedule' and config['watch'] is True
    assert config['rescan_of'] == str(first.id) and config['image']['reference'] == REFERENCE and new.repository_id == first.repository_id
    assert db.scalar(select(ScanJob.status).where(ScanJob.scan_id == new.id)) == 'QUEUED'
    # пока перепроверка не закончилась, вторая не создаётся
    assert image_rescan.rescan_due(db, timedelta(hours=0)) == []


def test_failed_check_is_retried_after_the_interval(client, db, worker_db, monkeypatch):
    repo = repository(client)
    failed = finish(db, repo, REFERENCE, watch=True, fail=True, monkeypatch=monkeypatch)
    assert failed.status == ScanStatus.FAILED
    assert len(image_rescan.rescan_due(db, timedelta(hours=1), now=datetime.now(UTC) + timedelta(hours=2))) == 1


def test_oldest_first_and_limit(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, OTHER, watch=True, monkeypatch=monkeypatch)
    age(db, 10)
    finish(db, repo, REFERENCE, watch=True, monkeypatch=monkeypatch)
    later = datetime.now(UTC) + timedelta(hours=30)
    one = image_rescan.rescan_due(db, timedelta(hours=24), now=later)
    assert [s.scanner_config['image']['reference'] for s in one] == [OTHER]
    db.execute(text("UPDATE scan_jobs SET status = 'COMPLETED'"))
    db.execute(text("UPDATE scans SET status = 'COMPLETED', completed_at = now() WHERE id = :id"), {'id': one[0].id})
    db.commit()
    db.expire_all()  # сессия тестов не сбрасывает объекты после commit
    both = image_rescan.rescan_due(db, timedelta(hours=24), limit=5, now=later + timedelta(hours=30))
    assert {s.scanner_config['image']['reference'] for s in both} == {OTHER, REFERENCE}


def test_full_queue_stops_quietly(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, REFERENCE, watch=True, monkeypatch=monkeypatch)
    monkeypatch.setattr(image_jobs, 'QUEUE_LIMIT', 0)
    assert image_rescan.rescan_due(db, timedelta(hours=0)) == []
    monkeypatch.setattr(image_jobs, 'QUEUE_LIMIT', 10)
    assert len(image_rescan.rescan_due(db, timedelta(hours=0))) == 1  # после освобождения очереди перепроверка не потеряна


def test_image_that_can_no_longer_be_checked_is_skipped(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, REFERENCE, watch=True, monkeypatch=monkeypatch)
    finish(db, repo, OTHER, watch=True, monkeypatch=monkeypatch)
    age(db, 1)
    monkeypatch.setenv('IMAGE_ALLOWED_REGISTRIES', 'registry.example')  # реестр убрали из разрешённых
    assert image_rescan.rescan_due(db, timedelta(hours=0), limit=5) == []
    monkeypatch.setenv('IMAGE_ALLOWED_REGISTRIES', 'localhost:5001')
    assert len(image_rescan.rescan_due(db, timedelta(hours=0), limit=5)) == 2


def test_poll_once_respects_the_setting(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, REFERENCE, watch=True, monkeypatch=monkeypatch)
    age(db, 48)
    monkeypatch.setattr(get_settings(), 'image_rescan_hours', 0)
    assert image_rescan.poll_once() == []
    monkeypatch.setattr(get_settings(), 'image_rescan_hours', 24)
    created = image_rescan.poll_once()
    assert len(created) == 1 and created[0]['image'] == REFERENCE
    db.expire_all()
    assert db.get(Scan, uuid.UUID(created[0]['scan_id'])).scanner_config['trigger'] == 'schedule'
    assert image_rescan.poll_once() == []  # уже поставлена в очередь


def test_poll_once_does_nothing_when_another_worker_holds_the_lock(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, REFERENCE, watch=True, monkeypatch=monkeypatch)
    age(db, 48)
    monkeypatch.setattr(get_settings(), 'image_rescan_hours', 24)
    other = Session(db.get_bind())
    try:
        assert other.scalar(text('SELECT pg_try_advisory_lock(:k)'), {'k': image_rescan.LOCK})
        assert image_rescan.poll_once() == []
    finally:
        other.execute(text('SELECT pg_advisory_unlock(:k)'), {'k': image_rescan.LOCK})
        other.close()
    assert len(image_rescan.poll_once()) == 1  # блокировка освобождена: работа идёт


def test_poll_once_releases_its_lock(client, db, worker_db, monkeypatch):
    monkeypatch.setattr(get_settings(), 'image_rescan_hours', 24)
    for _ in range(3):  # несколько вызовов подряд: блокировка не должна «залипать» на соединении из пула
        assert image_rescan.poll_once() == []
        probe = Session(db.get_bind())
        try:
            assert probe.scalar(text('SELECT pg_try_advisory_lock(:k)'), {'k': image_rescan.LOCK}) is True
        finally:
            probe.execute(text('SELECT pg_advisory_unlock(:k)'), {'k': image_rescan.LOCK})
            probe.close()


def test_worker_loop_runs_the_rescan_tick(monkeypatch):
    ticks = []
    monkeypatch.setattr(worker, 'log_trivy_storage', lambda: None)
    monkeypatch.setattr(worker, 'cleanup_orphans', lambda: None)
    monkeypatch.setattr(worker, 'recover_stale_jobs', lambda: None)
    monkeypatch.setattr('app.continuous.poll_once', lambda: None)
    monkeypatch.setattr(image_rescan, 'poll_once', lambda: ticks.append(1))

    def stop():
        raise KeyboardInterrupt
    monkeypatch.setattr(worker, 'claim_job', stop)
    worker.main()
    assert ticks == [1]


def test_rescan_runs_through_the_worker_and_is_compared(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, REFERENCE, watch=True, trigger='ci', monkeypatch=monkeypatch)
    age(db, 48)
    monkeypatch.setattr(get_settings(), 'image_rescan_hours', 24)
    new = image_rescan.poll_once()[0]
    monkeypatch.setattr(image_pipeline, 'run_image_scan', lambda ref: scan_result())
    worker.process_job(worker.claim_job())
    report = client.get(f"/api/checks/{new['scan_id']}/report").json()
    assert report['subject']['trigger'] == 'schedule' and report['check']['status'] == 'COMPLETED'
    assert report['changes_since_previous']['same_image'] is True and report['changes_since_previous']['new'] == 0


# ---- сравнение с предыдущей проверкой ----

def test_first_check_has_nothing_to_compare(client, db, worker_db, monkeypatch):
    scan = finish(db, repository(client), monkeypatch=monkeypatch)
    assert client.get(f'/api/checks/{scan.id}/report').json()['changes_since_previous'] is None


def test_same_image_with_new_findings_means_new_vulnerability_data(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, drop=3, monkeypatch=monkeypatch)
    second = finish(db, repo, monkeypatch=monkeypatch)
    changes = client.get(f'/api/checks/{second.id}/report').json()['changes_since_previous']
    assert changes['same_image'] is True and changes['new'] == 3 and changes['fixed'] == 0 and changes['unchanged'] == 11
    assert len(changes['new_findings']) == 3 and changes['new_findings_truncated'] is False
    assert 'Образ тот же' in changes['explanation'] and 'Сам образ не менялся' in changes['explanation']
    assert set(changes['new_findings'][0]) == {'finding_id', 'rule_id', 'cve', 'severity', 'component', 'installed_version'}
    assert changes['previous_image_digest'] == DIGEST


def test_changed_image_with_fixed_findings(client, db, worker_db, monkeypatch):
    repo = repository(client)
    first = finish(db, repo, monkeypatch=monkeypatch)
    second = finish(db, repo, digest=DIGEST2, drop=4, monkeypatch=monkeypatch)
    changes = client.get(f'/api/checks/{second.id}/report').json()['changes_since_previous']
    assert changes['same_image'] is False and changes['new'] == 0 and changes['fixed'] == 4 and changes['unchanged'] == 10
    assert changes['previous_check_id'] == str(first.id) and 'Образ изменился, новых находок нет' in changes['explanation']


def test_changed_image_with_new_findings_does_not_blame_the_database(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, drop=2, monkeypatch=monkeypatch)
    second = finish(db, repo, digest=DIGEST2, monkeypatch=monkeypatch)
    changes = client.get(f'/api/checks/{second.id}/report').json()['changes_since_previous']
    assert changes['same_image'] is False and changes['new'] == 2
    assert 'Образ изменился' in changes['explanation'] and 'Сам образ не менялся' not in changes['explanation']


def test_failed_checks_are_never_a_baseline(client, db, worker_db, monkeypatch):
    repo = repository(client)
    good = finish(db, repo, drop=1, monkeypatch=monkeypatch)
    finish(db, repo, fail=True, monkeypatch=monkeypatch)  # неполная проверка: сравнивать с ней нельзя
    third = finish(db, repo, monkeypatch=monkeypatch)
    changes = client.get(f'/api/checks/{third.id}/report').json()['changes_since_previous']
    assert changes['previous_check_id'] == str(good.id) and changes['new'] == 1
    failed = db.scalar(select(Scan).where(Scan.status == ScanStatus.FAILED))
    assert client.get(f'/api/checks/{failed.id}/report').json()['changes_since_previous'] is None


def test_other_images_are_not_compared(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, OTHER, drop=5, monkeypatch=monkeypatch)
    second = finish(db, repo, REFERENCE, monkeypatch=monkeypatch)
    assert client.get(f'/api/checks/{second.id}/report').json()['changes_since_previous'] is None


def test_new_builds_of_the_same_image_are_compared_even_with_different_tags(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, 'localhost:5001/bultshield-demo-app:build-1', drop=1, monkeypatch=monkeypatch)
    second = finish(db, repo, 'localhost:5001/bultshield-demo-app@' + DIGEST2, digest=DIGEST2, monkeypatch=monkeypatch)
    changes = client.get(f'/api/checks/{second.id}/report').json()['changes_since_previous']
    assert changes and changes['new'] == 1 and changes['same_image'] is False


def test_os_findings_match_even_when_the_image_reference_is_written_differently(client, db, worker_db, monkeypatch):
    """Регрессия: в живой проверке имя цели ОС содержит ссылку на образ (тег или digest), и сравнение видело сотни «новых» находок."""
    repo = repository(client)

    def retarget(findings, reference):
        return [{**f, 'file': f'{reference} (debian 12.15)'} if f['origin'] == 'os' else f for f in findings]
    scan_a = create_image_scan(db, repo, REFERENCE)

    def run_with(reference):
        def run(ref):
            base = scan_result()
            return ImageScanResult(ref, DIGEST, base.platform, base.db_updated_at,
                                   replace(base.report, findings=retarget(base.report.findings, reference)))
        return run
    monkeypatch.setattr(image_pipeline, 'run_image_scan', run_with(REFERENCE))
    worker.process_job(worker.claim_job())
    scan_b = create_image_scan(db, repo, REFERENCE)
    monkeypatch.setattr(image_pipeline, 'run_image_scan', run_with('localhost:5001/bultshield-demo-app@' + DIGEST))
    worker.process_job(worker.claim_job())
    db.expire_all()
    changes = client.get(f'/api/checks/{scan_b.id}/report').json()['changes_since_previous']
    assert changes['previous_check_id'] == str(scan_a.id)
    assert changes['new'] == 0 and changes['fixed'] == 0 and changes['unchanged'] == 14


def test_unknown_digest_is_not_guessed(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, drop=1, monkeypatch=monkeypatch)
    second = finish(db, repo, monkeypatch=monkeypatch)
    db.execute(text("UPDATE scans SET scanner_results = scanner_results #- '{trivy,digest}' WHERE id = :id"), {'id': second.id})
    db.commit()
    db.expire_all()
    changes = compare_with_previous(db, db.get(Scan, second.id), [])
    assert changes['same_image'] is None and 'нельзя' in changes['explanation']


def test_unfinished_and_source_checks_have_no_comparison(client, db, worker_db, monkeypatch):
    repo = repository(client)
    finish(db, repo, monkeypatch=monkeypatch)
    source = client.post('/api/checks', json={'repository_id': str(repo)}).json()
    assert client.get(f"/api/checks/{source['id']}/report").json()['changes_since_previous'] is None
    queued = create_image_scan(db, repo, REFERENCE)
    assert client.get(f'/api/checks/{queued.id}/report').json()['changes_since_previous'] is None


# ---- скрипт CI ----

class FakeApi(BaseHTTPRequestHandler):
    """Подставной сервер BultShield: запоминает запросы, отвечает по сценарию."""
    script = {}
    seen = []

    def _reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        FakeApi.seen.append((self.command, self.path, dict(self.headers), body))
        if self.command == 'POST':
            if 'redirect' in FakeApi.script:
                self.send_response(302)
                self.send_header('Location', FakeApi.script['redirect'])
                self.end_headers()
                return
            return self._reply(*FakeApi.script.get('post', (202, {'id': 'c1', 'status': 'QUEUED'})))
        if self.path.endswith('/report?limit=1'):
            return self._reply(*FakeApi.script.get('report', (200, REPORT)))
        statuses = FakeApi.script.setdefault('states', [(200, {'id': 'c1', 'status': 'COMPLETED'})])
        return self._reply(*(statuses.pop(0) if len(statuses) > 1 else statuses[0]))

    do_GET = do_POST = _handle

    def log_message(self, *args):
        pass


REPORT = {'verdict': {'result': 'FINDINGS', 'statement': 'Найдено 14 находок.'},
          'facts': {'total_findings': 14, 'by_severity': {'high': 5}, 'by_status': {'FOUND': 14}},
          'changes_since_previous': {'new': 2, 'fixed': 1, 'explanation': 'Образ тот же, но появились новые находки.'}}


def serve(handler=FakeApi):
    server = HTTPServer(('127.0.0.1', 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def fake_api():
    FakeApi.script, FakeApi.seen = {}, []
    server = serve()
    yield f'http://127.0.0.1:{server.server_address[1]}'
    server.shutdown()
    server.server_close()


def ci(url, *args, token=TOKEN, repo='r1', **env):
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('BULTSHIELD_', 'GITHUB_'))}
    environment.update({'BULTSHIELD_URL': url, 'BULTSHIELD_REPOSITORY_ID': repo, **({'BULTSHIELD_TOKEN': token} if token else {}), **env})
    return subprocess.run([sys.executable, str(SCRIPTS / 'ci_check.py'), '--image', 'localhost:5001/app@' + DIGEST, *args],
                          capture_output=True, text=True, env=environment, timeout=60)


def test_ci_script_queues_the_check_and_does_not_block(fake_api):
    done = ci(fake_api, '--watch')
    assert done.returncode == 0 and 'поставлена в очередь: c1' in done.stdout and '/api/checks/c1/report' in done.stdout
    method, path, headers, body = FakeApi.seen[0]
    assert (method, path) == ('POST', '/api/checks')
    assert body == {'repository_id': 'r1', 'image': 'localhost:5001/app@' + DIGEST, 'watch': True, 'trigger': 'ci'}
    assert headers['Authorization'] == f'Bearer {TOKEN}'
    assert TOKEN not in done.stdout + done.stderr and len(FakeApi.seen) == 1  # без --wait ничего не опрашивает


def test_ci_script_without_token_sends_no_authorization(fake_api):
    done = ci(fake_api, token='')
    assert done.returncode == 0 and 'Authorization' not in FakeApi.seen[0][2]


def test_ci_script_waits_and_shows_the_result(fake_api):
    FakeApi.script['states'] = [(200, {'id': 'c1', 'status': 'RUNNING'}), (200, {'id': 'c1', 'status': 'COMPLETED'})]
    done = ci(fake_api, '--wait', '30')
    assert done.returncode == 0, done.stderr
    assert 'Итог: Найдено 14 находок.' in done.stdout and 'Находок: 14' in done.stdout
    assert 'С прошлой проверки образа: новых 2, исправлено 1' in done.stdout and 'не гарантия' in done.stdout


def test_ci_script_reports_a_failed_check_loudly(fake_api):
    FakeApi.script['post'] = (202, {'id': 'c1', 'status': 'QUEUED'})
    FakeApi.script['states'] = [(200, {'id': 'c1', 'status': 'FAILED', 'error_message': 'Trivy завершился с ошибкой', 'error_code': 'SCANNER_FAILED'})]
    done = ci(fake_api, '--wait', '30')
    assert done.returncode == 0
    assert 'ПРОВЕРКА ЗАВЕРШИЛАСЬ ОШИБКОЙ' in done.stdout and 'Это не значит, что уязвимостей нет' in done.stdout and 'Итог:' not in done.stdout
    assert ci(fake_api, '--wait', '30', '--strict').returncode == 2


def test_ci_script_findings_never_change_the_exit_code(fake_api):
    done = ci(fake_api, '--wait', '30', '--strict')
    assert done.returncode == 0 and 'Найдено 14 находок' in done.stdout


def test_ci_script_warns_when_the_result_is_late(fake_api):
    FakeApi.script['states'] = [(200, {'id': 'c1', 'status': 'RUNNING'})]
    done = ci(fake_api, '--wait', '1')
    assert done.returncode == 0 and 'результат не получен за 1 с' in done.stdout and 'Итог:' not in done.stdout


@pytest.mark.parametrize('status, detail, expected', [
    (401, None, 'не принял токен'), (403, None, 'запрещено'), (404, None, 'репозиторий не найден'),
    (409, 'уже идёт', 'уже идёт другая проверка: уже идёт'), (422, 'Образ вне разрешённых реестров', 'запрос отклонён: Образ вне разрешённых реестров'),
    (429, 'Очередь заполнена', 'очередь проверок заполнена'), (500, None, 'неожиданный ответ сервера (HTTP 500)'),
])
def test_ci_script_explains_refusals_and_still_does_not_block(fake_api, status, detail, expected):
    FakeApi.script['post'] = (status, {'detail': detail})
    done = ci(fake_api)
    assert done.returncode == 0 and 'ПРОВЕРКА НЕ ЗАПУЩЕНА' in done.stdout and expected in done.stdout
    assert 'это не значит, что уязвимостей нет' in done.stdout and 'Деплой не блокируется' in done.stdout
    assert ci(fake_api, '--strict').returncode == 2


def test_ci_script_survives_an_unreachable_server():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    done = ci(f'http://127.0.0.1:{port}')
    assert done.returncode == 0 and 'ПРОВЕРКА НЕ ЗАПУЩЕНА' in done.stdout and 'сервис проверки недоступен' in done.stdout
    assert 'Traceback' not in done.stderr and ci(f'http://127.0.0.1:{port}', '--strict').returncode == 2


def test_ci_script_needs_url_and_repository():
    for env in ({'BULTSHIELD_URL': ''}, {'BULTSHIELD_REPOSITORY_ID': ''}):
        done = ci('http://127.0.0.1:1', **{'repo': 'r1', **env}) if 'BULTSHIELD_URL' in env else ci('http://127.0.0.1:1', repo='')
        assert done.returncode == 0 and 'не заданы BULTSHIELD_URL' in done.stdout


def test_ci_script_never_sends_the_token_over_plain_http_to_a_remote_host():
    done = ci('http://bultshield.example.com')
    assert 'нельзя отправлять по http' in done.stdout and 'недоступен' not in done.stdout and TOKEN not in done.stdout


def test_ci_script_does_not_follow_redirects_with_the_token(fake_api):
    spy_seen = []

    class Spy(BaseHTTPRequestHandler):
        def do_POST(self):
            spy_seen.append(dict(self.headers))
            self.send_response(200)
            self.end_headers()
        do_GET = do_POST

        def log_message(self, *args):
            pass
    spy = serve(Spy)
    try:
        FakeApi.script['redirect'] = f'http://127.0.0.1:{spy.server_address[1]}/steal'
        done = ci(fake_api)
    finally:
        spy.shutdown()
        spy.server_close()
    assert spy_seen == [] and 'ПРОВЕРКА НЕ ЗАПУЩЕНА' in done.stdout and TOKEN not in done.stdout


def test_ci_script_emits_a_github_warning(fake_api):
    FakeApi.script['post'] = (404, {'detail': None})
    done = ci(fake_api, GITHUB_ACTIONS='true')
    assert done.stdout.startswith('::warning title=BultShield::ПРОВЕРКА НЕ ЗАПУЩЕНА') and done.returncode == 0


def test_ci_script_against_the_real_application(db, client):
    repo = repository(client)
    config = uvicorn.Config(create_app(), host='127.0.0.1', port=0, log_level='error')
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    try:
        port = server.servers[0].sockets[0].getsockname()[1]
        done = ci(f'http://127.0.0.1:{port}', '--watch', token='', repo=str(repo))
    finally:
        server.should_exit = True
        thread.join(10)
    assert done.returncode == 0 and 'поставлена в очередь' in done.stdout, done.stdout + done.stderr
    scan = db.scalar(select(Scan).where(Scan.kind == 'image'))
    assert scan.scanner_config['watch'] is True and scan.scanner_config['trigger'] == 'ci'
    assert scan.scanner_config['image']['reference'] == 'localhost:5001/app@' + DIGEST


def test_workflow_example_is_a_template_that_does_not_block():
    text_ = (Path(__file__).resolve().parents[2] / 'docs' / 'ci' / 'github-actions-example.yml').read_text()
    assert 'continue-on-error: true' in text_ and 'secrets.BULTSHIELD_TOKEN' in text_ and '--watch' in text_
    assert 'ghp_' not in text_ and 'BULTSHIELD_TOKEN: ' in text_ and '.github/workflows' in text_


# ---- ручной запуск перепроверки ----

def rescan_script(*args):
    return subprocess.run([sys.executable, str(SCRIPTS / 'run_image_rescan.py'), *args], capture_output=True, text=True,
                          env={**os.environ, 'IMAGE_ALLOWED_REGISTRIES': 'localhost:5001'}, cwd=BACKEND, timeout=120)


def test_rescan_script_lists_and_queues(client, db, worker_db, monkeypatch):
    repo = repository(client)
    first = finish(db, repo, watch=True, monkeypatch=monkeypatch)
    listed = rescan_script('--list')
    assert listed.returncode == 0, listed.stderr
    assert REFERENCE in listed.stdout and 'COMPLETED' in listed.stdout and 'Под наблюдением образов: 1' in listed.stdout
    assert 'Нет образов, которые пора перепроверить' in rescan_script().stdout  # свежая проверка: срок не вышел
    queued = rescan_script('--older-than-hours', '0')
    assert queued.returncode == 0 and 'В очередь поставлена перепроверка' in queued.stdout and str(first.id) in queued.stdout
    scans = db.scalars(select(Scan).where(Scan.kind == 'image').order_by(Scan.created_at)).all()
    assert len(scans) == 2 and scans[1].scanner_config['trigger'] == 'schedule'
    assert 'Нет образов, которые пора перепроверить' in rescan_script('--older-than-hours', '0').stdout  # вторая уже в очереди

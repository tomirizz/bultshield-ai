"""Пояснения модели как фоновое задание: постановка, повторный запрос, недоступная модель, сбои, права доступа."""
import os
import uuid

import pytest
from app import llm_explain, llm_jobs
from app.check_report import load_report
from app.config import get_settings
from app.llm_jobs import process_next
from app.models import LLMCall, LLMJob, Scan
from app.tenant import isolate
from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from test_fix_runs import allow_local_registry as allow_local_registry
from test_fix_runs import check as check
from test_gitleaks import worker_db as worker_db  # noqa: F401


def model(monkeypatch, provider='fake', **changes):
    """Подключает тестовую модель так, как это делают настройки сервера."""
    settings = get_settings().model_copy(update={'llm_provider': provider, **changes})
    monkeypatch.setattr(llm_jobs, 'get_settings', lambda: settings)
    monkeypatch.setattr(llm_explain, 'get_settings', lambda: settings)
    return settings


def jobs(db):
    db.expire_all()
    return db.scalars(select(LLMJob).order_by(LLMJob.created_at, LLMJob.id)).all()


def calls(db):
    db.expire_all()
    return db.scalars(select(LLMCall)).all()


def report(client, check_id):
    return client.get(f'/api/checks/{check_id}/report?limit=500').json()


def facts(rep):
    return {k: v for k, v in rep.items() if k not in ('llm', 'assumptions', 'limitations')}


def test_request_is_refused_while_the_model_is_not_connected(client, db, check, monkeypatch):
    model(monkeypatch, 'disabled')
    response = client.post(f'/api/checks/{check}/explanations')
    assert response.status_code == 409 and 'Модель не подключена' in response.json()['detail']
    assert jobs(db) == []   # задание, которое молча ничего не сделает, не создаётся


def test_request_is_queued_and_the_worker_finishes_it(client, db, check, monkeypatch):
    model(monkeypatch)
    before = facts(report(client, check))
    response = client.post(f'/api/checks/{check}/explanations')
    assert response.status_code == 202
    body = response.json()
    assert body['status'] == 'QUEUED' and body['already_running'] is False and body['check_id'] == str(check)
    # Пока задание не выполнено, отчёт не выглядит так, будто пояснений не будет.
    queued = report(client, check)['llm']
    assert queued['status'] == 'PENDING' and queued['job']['status'] == 'QUEUED'
    state = client.get(f'/api/checks/{check}/explanations').json()
    assert state['job']['id'] == body['id'] and state['llm']['status'] == 'PENDING'

    assert process_next() is True
    done = client.get(f'/api/checks/{check}/explanations').json()
    assert done['job']['status'] == 'COMPLETED' and done['job']['completed_at'] and done['job']['started_at']
    assert done['job']['result']['completed'] >= 1 and done['llm']['status'] in ('COMPLETED', 'PARTIAL')
    full = report(client, check)
    assert [a for a in full['assumptions'] if a['source'] == 'llm_explanation']
    assert facts(full) == before   # пояснения — предположения: факты и статусы не меняются
    assert process_next() is False


def test_repeated_request_does_not_create_a_second_job(client, db, check, monkeypatch):
    model(monkeypatch)
    first = client.post(f'/api/checks/{check}/explanations').json()
    second = client.post(f'/api/checks/{check}/explanations')
    assert second.status_code == 202 and second.json()['id'] == first['id'] and second.json()['already_running'] is True
    assert len(jobs(db)) == 1
    process_next()
    assert client.post(f'/api/checks/{check}/explanations').json()['already_running'] is False   # прежнее завершено: новое задание
    assert len(jobs(db)) == 2


def test_second_job_does_not_pay_for_explanations_already_received(client, db, check, monkeypatch):
    model(monkeypatch)
    client.post(f'/api/checks/{check}/explanations')
    process_next()
    first = len(calls(db))
    client.post(f'/api/checks/{check}/explanations')
    process_next()
    assert len(calls(db)) == first
    assert jobs(db)[1].summary['completed'] == 0 and jobs(db)[1].summary['reused'] == first


def test_two_active_jobs_for_one_check_are_impossible_in_the_database(db, check):
    scan = db.get(Scan, check)
    db.add(LLMJob(project_id=scan.project_id, scan_id=scan.id))
    db.commit()
    db.add(LLMJob(project_id=scan.project_id, scan_id=scan.id))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_unavailable_model_finishes_the_job_and_changes_nothing_else(client, db, check, monkeypatch):
    model(monkeypatch, llm_fake_mode='unavailable')
    before = facts(report(client, check))
    client.post(f'/api/checks/{check}/explanations')
    assert process_next() is True
    job = client.get(f'/api/checks/{check}/explanations').json()
    assert job['job']['status'] == 'COMPLETED' and job['job']['result']['status'] == 'UNAVAILABLE'
    assert job['llm']['status'] == 'UNAVAILABLE' and 'Результаты сканеров' in job['llm']['message']
    after = report(client, check)
    assert facts(after) == before and not [a for a in after['assumptions'] if a['source'] == 'llm_explanation']


def test_garbage_from_the_model_is_not_used(client, db, check, monkeypatch):
    model(monkeypatch, llm_fake_mode='garbage')
    client.post(f'/api/checks/{check}/explanations')
    process_next()
    state = client.get(f'/api/checks/{check}/explanations').json()
    assert state['llm']['status'] == 'FAILED' and not [a for a in report(client, check)['assumptions'] if a['source'] == 'llm_explanation']


def test_unexpected_error_fails_the_job_without_leaking_details(client, db, check, monkeypatch):
    model(monkeypatch)

    def boom(*args, **kwargs):
        raise RuntimeError('password=hunter2 at /srv/internal/path')
    monkeypatch.setattr(llm_explain, 'explain_check', boom)
    client.post(f'/api/checks/{check}/explanations')
    assert process_next() is True
    job = client.get(f'/api/checks/{check}/explanations').json()['job']
    assert job['status'] == 'FAILED' and 'hunter2' not in str(job) and '/srv' not in str(job)
    rep = report(client, check)['llm']
    assert rep['status'] == 'FAILED' and 'Результаты сканеров и статусы от этого не зависят' in rep['message']


def test_stuck_job_is_failed_and_can_be_requested_again(client, db, check, monkeypatch):
    model(monkeypatch)
    job_id = client.post(f'/api/checks/{check}/explanations').json()['id']
    db.execute(update(LLMJob).where(LLMJob.id == uuid.UUID(job_id)).values(status='RUNNING', started_at=text("now() - interval '1 hour'")))
    db.commit()
    assert client.post(f'/api/checks/{check}/explanations').json()['already_running'] is True   # пока не признано зависшим
    assert process_next() is False
    stuck = jobs(db)[0]
    assert stuck.status == 'FAILED' and 'Время обработки истекло' in stuck.error_message
    assert client.post(f'/api/checks/{check}/explanations').json()['already_running'] is False


def test_unknown_unfinished_and_service_checks_are_refused(client, db, check, monkeypatch):
    model(monkeypatch)
    assert client.post(f'/api/checks/{uuid.uuid4()}/explanations').status_code == 404
    assert client.get(f'/api/checks/{uuid.uuid4()}/explanations').status_code == 404
    db.execute(update(Scan).where(Scan.id == check).values(status='FAILED'))
    db.commit()
    response = client.post(f'/api/checks/{check}/explanations')
    assert response.status_code == 409 and 'пояснять пока нечего' in response.json()['detail']
    assert jobs(db) == []
    db.execute(update(Scan).where(Scan.id == check).values(status='COMPLETED', kind='verification'))
    db.commit()
    assert client.post(f'/api/checks/{check}/explanations').status_code == 404


def test_full_queue_is_refused(client, db, check, monkeypatch):
    model(monkeypatch)
    monkeypatch.setattr(llm_jobs, 'QUEUE_LIMIT', 0)
    assert client.post(f'/api/checks/{check}/explanations').status_code == 429
    assert jobs(db) == []


def test_state_without_a_job_says_nothing_was_requested(client, check, monkeypatch):
    model(monkeypatch)
    state = client.get(f'/api/checks/{check}/explanations').json()
    assert state['job'] is None and state['llm']['status'] == 'NOT_RUN'


def test_jobs_belong_to_their_owner_and_go_with_the_check(db, check):
    from app.api import WORKSPACE_USER_ID
    scan = db.get(Scan, check)
    db.add(LLMJob(project_id=scan.project_id, scan_id=scan.id))
    db.commit()
    with Session(db.get_bind()) as outsider:
        isolate(outsider, uuid.uuid4())
        assert outsider.scalars(select(LLMJob)).all() == []
    with Session(db.get_bind()) as owner:
        isolate(owner, WORKSPACE_USER_ID)
        assert len(owner.scalars(select(LLMJob)).all()) == 1
    db.execute(text('DELETE FROM scans WHERE id = :id'), {'id': check})
    db.commit()
    assert jobs(db) == []


def test_worker_takes_explanation_jobs_when_there_are_no_scans(monkeypatch):
    """Цикл worker вызывает обработку пояснений, когда проверок в очереди нет."""
    from app import worker
    seen = []
    monkeypatch.setattr(worker, 'cleanup_orphans', lambda: None)
    monkeypatch.setattr(worker, 'log_trivy_storage', lambda: None)
    monkeypatch.setattr(worker, 'recover_stale_jobs', lambda: None)
    monkeypatch.setattr(worker, 'claim_job', lambda: None)
    monkeypatch.setattr('app.continuous.poll_once', lambda: None)
    monkeypatch.setattr('app.image_rescan.poll_once', lambda: None)
    monkeypatch.setattr('app.fix_service.process_next', lambda: False)
    monkeypatch.setattr('app.security_agent.process_next', lambda: False)

    def explanations():
        seen.append(1)
        raise KeyboardInterrupt
    monkeypatch.setattr('app.llm_jobs.process_next', explanations)
    worker.main()
    assert seen == [1]


def test_report_loader_still_works_without_any_job(db, check):
    assert load_report(db, db.get(Scan, check), limit=5)['llm']['job'] is None


# ---- скрипт scripts/request_explanations.py ----

def test_script_waits_for_the_job_and_prints_the_result(check, monkeypatch):
    import subprocess
    import sys
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from pathlib import Path

    import json

    steps = []

    class Api(BaseHTTPRequestHandler):
        def _send(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            steps.append('POST')
            self._send(202, {'id': 'j1', 'status': 'QUEUED', 'already_running': False})

        def do_GET(self):
            if self.path.endswith('/report?limit=500'):
                return self._send(200, {'assumptions': [{'source': 'llm_explanation', 'subject': 'package:lodash@4.17.15', 'model': 'fake',
                                                         'explanation': 'Пакет устарел.', 'recommended_fix': 'Обновить до 4.17.21.'}]})
            steps.append('GET')
            done = steps.count('GET') > 1
            job = {'id': 'j1', 'status': 'COMPLETED' if done else 'RUNNING', 'error': None,
                   'result': {'status': 'COMPLETED', 'completed': 3, 'reused': 0, 'failed': 0, 'skipped': 0,
                              'input_tokens': 100, 'output_tokens': 20, 'cost_usd': 0.0}}
            self._send(200, {'job': job, 'llm': {'status': 'COMPLETED', 'message': 'Модель пояснила групп находок: 3.', 'failures': []}})

        def log_message(self, *args):
            pass

    server = HTTPServer(('127.0.0.1', 0), Api)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    script = Path(__file__).resolve().parents[2] / 'scripts' / 'request_explanations.py'
    out = subprocess.run([sys.executable, str(script), 'c1', '--url', f'http://127.0.0.1:{server.server_port}', '--wait', '30'],
                         capture_output=True, text=True, timeout=60)
    server.shutdown()
    assert out.returncode == 0, out.stderr
    assert 'Получено: 3' in out.stdout and 'Раздел llm отчёта: COMPLETED' in out.stdout and 'Обновить до 4.17.21' in out.stdout


def test_script_reports_an_unreachable_server_without_claiming_anything():
    import subprocess
    import sys
    from pathlib import Path
    script = Path(__file__).resolve().parents[2] / 'scripts' / 'request_explanations.py'
    out = subprocess.run([sys.executable, str(script), 'c1', '--url', 'http://127.0.0.1:9', '--wait', '1'], capture_output=True, text=True, timeout=30)
    assert out.returncode != 0 and 'не меняет результаты проверки' in out.stderr
    out = subprocess.run([sys.executable, str(script), 'c1'], capture_output=True, text=True, timeout=30, env={'PATH': os.environ['PATH']})
    assert out.returncode != 0 and 'Укажите адрес сервера' in out.stderr

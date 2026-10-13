"""Live legacy-owner requests must not deadlock against the audit middleware."""
from uuid import UUID

import pytest
from app.api import WORKSPACE_USER_ID, queue_source_scan
from app.image_jobs import create_image_scan
from app.models import AuditEvent
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session


@pytest.mark.parametrize('kind', ['image', 'same_commit', 'already_running'])
def test_queue_response_allows_audit_before_request_session_closes(client, db, engine, monkeypatch, kind):
    monkeypatch.setenv('IMAGE_ALLOWED_REGISTRIES', 'localhost:5001')
    project = client.post('/api/projects', json={'name': 'audit-lock', 'repository': {
        'url': 'https://github.com/example/demo', 'default_branch': 'main'}}).json()
    repository = UUID(project['repositories'][0]['id'])
    if kind == 'image':
        first = create_image_scan(db, repository, 'localhost:5001/demo:main')
        assert create_image_scan(db, repository, 'localhost:5001/demo:main').id == first.id
    else:
        first = queue_source_scan(repository, db, 'a' * 40)
        if kind == 'same_commit':
            assert queue_source_scan(repository, db, 'a' * 40).id == first.id
        else:
            with pytest.raises(HTTPException) as error:
                queue_source_scan(repository, db)
            assert error.value.status_code == 409
    # FastAPI's request dependency remains open while middleware writes its audit event.
    with Session(engine) as audit:
        audit.execute(text("SET LOCAL lock_timeout = '500ms'"))
        audit.add(AuditEvent(user_id=WORKSPACE_USER_ID, action='POST /api/checks', outcome='202'))
        audit.commit()

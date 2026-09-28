"""Metadata-only audit records: never store credentials, query strings or bodies."""
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import get_engine, get_session
from .models import AuditEvent

router = APIRouter(prefix='/api')


def record(user_id, action, object_id, outcome):
    with Session(get_engine()) as db, db.begin():
        db.add(AuditEvent(user_id=user_id, action=action[:100], object_id=object_id, outcome=outcome))


@router.get('/audit-log')
def audit_log(db: Annotated[Session, Depends(get_session)]):
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.id).limit(100)).all()
    return [{'at': e.created_at, 'action': e.action, 'object_id': e.object_id, 'outcome': e.outcome} for e in events]

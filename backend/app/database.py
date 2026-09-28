from collections.abc import Generator
from functools import lru_cache

from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings


@lru_cache
def get_engine():
    return create_engine(
        get_settings().database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        connect_args={"connect_timeout": 5},
    )


def get_session(request: Request) -> Generator[Session, None, None]:
    with sessionmaker(bind=get_engine(), expire_on_commit=False)() as session:
        if get_settings().authentication_required:
            from .tenant import isolate
            owner_id = getattr(request.state, 'user_id', None)
            if owner_id is None:
                from fastapi import HTTPException
                raise HTTPException(401, 'Войдите через GitHub.')
            isolate(session, owner_id)
        yield session

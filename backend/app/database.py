from collections.abc import Generator
from functools import lru_cache

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


def get_session() -> Generator[Session, None, None]:
    with sessionmaker(bind=get_engine(), expire_on_commit=False)() as session:
        yield session

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session


@pytest.fixture(scope="session")
def engine():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.fail("TEST_DATABASE_URL is required; tests need a real, disposable PostgreSQL database.")
    parsed = make_url(url)
    if parsed.host not in {"127.0.0.1", "localhost"} or not (parsed.database or "").endswith("_test"):
        pytest.fail("Refusing to run destructive tests outside a local *_test database.")
    os.environ["DATABASE_URL"] = url
    from app.config import get_settings
    from app.database import get_engine

    get_settings.cache_clear()
    get_engine.cache_clear()
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.upgrade(config, "head")
    result = create_engine(url)
    yield result
    result.dispose()
    get_engine().dispose()


@pytest.fixture(autouse=True)
def clean_database(engine):
    from app.models import Base

    names = ", ".join(f'"{table.name}"' for table in Base.metadata.sorted_tables)
    with engine.begin() as connection:
        connection.execute(text(f"TRUNCATE TABLE {names} CASCADE"))


@pytest.fixture
def client(engine):
    from app.main import create_app

    with TestClient(create_app()) as result:
        yield result


@pytest.fixture
def db(engine):
    with Session(engine, expire_on_commit=False) as session:
        yield session


@pytest.fixture(autouse=True)
def isolate_trivy(monkeypatch):
    from app import worker
    from app.trivy_runner import TrivyReport
    monkeypatch.setattr(worker, 'run_trivy', lambda path: TrivyReport([], {}))

import time

from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from .database import get_engine


def main():
    for attempt in range(30):
        try:
            with get_engine().connect() as connection:
                connection.execute(text("SELECT 1"))
            break
        except SQLAlchemyError:
            if attempt == 29:
                raise SystemExit("PostgreSQL is unavailable; refusing to start without the database.") from None
            print("Waiting for PostgreSQL...", flush=True)
            time.sleep(2)
    command.upgrade(Config("alembic.ini"), "head")
    print("BULTSHIELD_DATABASE_READY", flush=True)


if __name__ == "__main__":
    main()

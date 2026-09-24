from logging.config import fileConfig

from alembic import context
from app.config import get_settings
from app.models import Base
from sqlalchemy import create_engine, pool

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)


if context.is_offline_mode():
    context.configure(url=get_settings().database_url, target_metadata=Base.metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = create_engine(get_settings().database_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()

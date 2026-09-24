from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    app_env: str = "development"
    frontend_dist: Path = Path(__file__).resolve().parents[2] / "frontend" / "dist"

    @field_validator("database_url")
    @classmethod
    def postgres_only(cls, value: str) -> str:
        if value.startswith("postgres://"):
            value = value.replace("postgres://", "postgresql+psycopg://", 1)
        elif value.startswith("postgresql://"):
            value = value.replace("postgresql://", "postgresql+psycopg://", 1)
        if not value.startswith("postgresql+psycopg://"):
            raise ValueError("A PostgreSQL connection URL is required")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()

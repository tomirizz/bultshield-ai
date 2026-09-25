from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    app_env: str = "development"
    ai_enabled: bool = False
    ai_endpoint: str = "http://127.0.0.1:8081"
    ai_model: str = "qwen2.5-1.5b-instruct"
    ai_timeout_seconds: int = Field(default=240, ge=10, le=600)
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

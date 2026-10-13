import uuid
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    app_env: str = "development"
    auth_enabled: bool = False
    public_url: str = "https://bultshield-app-bultshield-ai-brick.fin1.bult.app"
    github_client_id: str = ""
    github_client_secret: str = ""
    github_token_key: str = ""
    legacy_owner_github_id: str = ""
    ai_enabled: bool = False
    ai_endpoint: str = "http://127.0.0.1:8081"
    ai_model: str = "qwen2.5-1.5b-instruct"
    ai_timeout_seconds: int = Field(default=240, ge=10, le=600)
    # Подключение внешней модели для пояснений. Ключ хранится только на сервере и не попадает в ответы API и логи.
    llm_provider: str = 'disabled'  # disabled | fake | bult | openai | anthropic
    llm_api_key: SecretStr = SecretStr('')
    llm_base_url: str = ''
    llm_model: str = ''
    llm_timeout_seconds: int = Field(default=30, ge=3, le=120)
    llm_max_output_tokens: int = Field(default=600, ge=100, le=2000)
    llm_max_input_chars: int = Field(default=6000, ge=500, le=20000)
    llm_max_calls_per_check: int = Field(default=20, ge=1, le=100)
    llm_daily_call_limit: int = Field(default=200, ge=1, le=10000)
    llm_price_input_per_mtok: float = Field(default=0, ge=0)
    llm_price_output_per_mtok: float = Field(default=0, ge=0)
    llm_fake_mode: str = 'ok'  # только для провайдера fake: ok | unavailable | garbage | invented_version | leak
    # Запуск проверок из CI. Токен выключен, пока не задан. Он даёт доступ только к запуску и чтению проверок от имени одного владельца.
    ci_trigger_token: SecretStr = SecretStr('')
    ci_trigger_owner_id: str = ''
    # Через сколько часов worker перепроверяет образы с пометкой «следить». 0 отключает автоматические перепроверки.
    image_rescan_hours: float = Field(default=24, ge=0, le=720)
    frontend_dist: Path = Path(__file__).resolve().parents[2] / "frontend" / "dist"

    @property
    def authentication_required(self) -> bool:
        return self.auth_enabled or self.app_env == 'production'

    @model_validator(mode='after')
    def ci_token_is_complete(self):
        token = self.ci_trigger_token.get_secret_value()
        if token:
            if len(token) < 32:
                raise ValueError('CI_TRIGGER_TOKEN: не короче 32 символов (например, python -c "import secrets; print(secrets.token_urlsafe(32))")')
            try:
                uuid.UUID(self.ci_trigger_owner_id)
            except ValueError:
                raise ValueError('CI_TRIGGER_OWNER_ID: нужен идентификатор пользователя-владельца проектов (UUID)') from None
        return self

    @field_validator('llm_provider')
    @classmethod
    def known_provider(cls, value):
        value = value.strip().lower()
        if value not in ('disabled', 'fake', 'bult', 'openai', 'anthropic'):
            raise ValueError('LLM_PROVIDER: disabled, fake, bult, openai или anthropic')
        return value

    @field_validator('public_url')
    @classmethod
    def public_origin(cls, value):
        from urllib.parse import urlsplit
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
            raise ValueError('PUBLIC_URL must be a HTTPS origin')
        return value.rstrip('/')

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

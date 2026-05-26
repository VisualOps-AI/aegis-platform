from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    environment: Environment = Environment.DEVELOPMENT

    openai_api_key: Annotated[str, Field(min_length=1)] | None = None
    openai_api_url: AnyHttpUrl = "https://api.openai.com/v1/chat/completions"

    db_path: Path = Path(__file__).parent / "overwatch.db"
    registry_path: Path = Path(__file__).parent / "registry.json"

    judge_model: str = "gpt-4o-mini"
    judge_max_tokens: int = 100
    judge_timeout: float = 30.0

    api_key: str | None = None
    require_api_key: bool = False

    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60

    air_gap_mode: bool = False
    alerting_enabled: bool = True
    alert_rate_limit_per_agent: int = 5
    alert_rate_limit_window_seconds: int = 60

    slack_webhook_url: str | None = None
    slack_channel: str | None = None
    slack_min_severity: str = "medium"

    pagerduty_routing_key: str | None = None
    pagerduty_min_severity: str = "high"

    webhook_url: str | None = None
    webhook_headers: str | None = None
    webhook_min_severity: str = "low"

    dashboard_password: str = "admin"

    log_level: str = "INFO"
    log_json: bool = False

    @field_validator("log_json", mode="after")
    @classmethod
    def json_logs_in_production(cls, v, info):
        if info.data.get("environment") == Environment.PRODUCTION:
            return True
        return v

    @field_validator("log_level", mode="after")
    @classmethod
    def set_production_log_level(cls, v, info):
        if info.data.get("environment") == Environment.PRODUCTION and v == "DEBUG":
            return "INFO"
        return v

    @field_validator("require_api_key", mode="after")
    @classmethod
    def require_key_in_production(cls, v, info):
        if info.data.get("environment") == Environment.PRODUCTION:
            return True
        return v

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.PRODUCTION

    @property
    def grading_enabled(self) -> bool:
        return self.openai_api_key is not None


@lru_cache
def get_settings() -> Settings:
    return Settings()

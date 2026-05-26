from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


class KillCheckFailMode(str, Enum):
    OPEN = "open"
    CLOSED = "closed"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    environment: Environment = Environment.DEVELOPMENT

    openai_api_key: Annotated[str, Field(min_length=1)]
    openai_api_url: AnyHttpUrl = "https://api.openai.com/v1/chat/completions"

    witness_governance_url: AnyHttpUrl | None = None
    overwatch_url: AnyHttpUrl | None = None
    witness_governance_enabled: bool | None = None
    overwatch_enabled: bool = True
    witness_api_key: str | None = None
    overwatch_api_key: str | None = None
    overwatch_verify_tls: bool = True
    witness_require_https: bool | None = None
    overwatch_require_https: bool = False

    witness_brain_url: AnyHttpUrl | None = None
    ml_brain_url: AnyHttpUrl | None = None

    agent_id: str = "witness-local-01"

    log_file: Path = Path(__file__).parent / "security_log.json"
    policy_file: Path = Path(__file__).parent / "policy_config.json"

    dlp_patterns: list[str] = ["sk-", "password"]
    forbidden_tools: list[str] = ["execute_command", "delete_file", "transfer_money"]

    admin_override_allowed: bool = True
    http_timeout: float = 120.0
    overwatch_timeout: float = 5.0
    prompt_snippet_max_length: int = 50

    injection_detection_enabled: bool = True
    injection_patterns_file: Path = Path(__file__).parent / "injection_patterns.json"
    injection_block_threshold: float = 0.5

    request_validation_enabled: bool = True
    max_payload_size_bytes: int = 1_000_000
    max_messages: int = 256
    max_message_content_length: int = 128_000

    kill_check_enabled: bool = True
    kill_check_fail_mode: KillCheckFailMode = KillCheckFailMode.OPEN
    kill_check_cache_ttl: float = 5.0
    kill_check_timeout: float = 2.0

    ml_brain_enabled: bool = False
    ml_brain_timeout: float = 1.0
    ml_brain_threshold: float = 0.5

    log_level: str = "INFO"
    log_json: bool = False

    @model_validator(mode="after")
    def resolve_backward_compat(self):
        if self.witness_governance_url is not None and self.overwatch_url is None:
            self.overwatch_url = self.witness_governance_url
        if self.witness_governance_enabled is not None:
            self.overwatch_enabled = self.witness_governance_enabled
        if self.witness_api_key is not None and self.overwatch_api_key is None:
            self.overwatch_api_key = self.witness_api_key
        if self.witness_require_https is not None:
            self.overwatch_require_https = self.witness_require_https
        if self.witness_brain_url is not None and self.ml_brain_url is None:
            self.ml_brain_url = self.witness_brain_url
        return self

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

    @field_validator("overwatch_url", mode="before")
    @classmethod
    def set_default_overwatch_url(cls, v):
        if v is None or v == "":
            return "http://localhost:9000/api/ingest"
        return v

    @field_validator("ml_brain_url", mode="before")
    @classmethod
    def set_default_ml_brain_url(cls, v):
        if v is None or v == "":
            return "http://localhost:5000"
        return v

    @field_validator("admin_override_allowed", mode="after")
    @classmethod
    def disable_override_in_production(cls, v, info):
        if info.data.get("environment") == Environment.PRODUCTION:
            return False
        return v

    @field_validator("overwatch_require_https", mode="after")
    @classmethod
    def require_https_in_production(cls, v, info):
        if info.data.get("environment") == Environment.PRODUCTION:
            return True
        return v

    @model_validator(mode="after")
    def validate_governance_https(self):
        if self.overwatch_require_https and self.overwatch_enabled:
            url = str(self.overwatch_url)
            if not url.startswith("https://"):
                raise ValueError(
                    f"Governance URL must use HTTPS in production mode. "
                    f"Current: {url}. Set WITNESS_REQUIRE_HTTPS=false to disable (not recommended)."
                )
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.PRODUCTION

    @property
    def overwatch_base_url(self) -> str:
        url = str(self.overwatch_url)
        if url.endswith("/api/ingest"):
            return url[:-11]
        return url.rstrip("/")

    @property
    def overwatch_ingest_url(self) -> str:
        url = str(self.overwatch_url)
        if not url.endswith("/api/ingest"):
            return url.rstrip("/") + "/api/ingest"
        return url

    @property
    def ml_brain_analyze_url(self) -> str:
        url = str(self.ml_brain_url)
        return url.rstrip("/") + "/analyze"


@lru_cache
def get_settings() -> Settings:
    return Settings()

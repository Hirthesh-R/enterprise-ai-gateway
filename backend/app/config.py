"""Application configuration.

All settings are loaded from environment variables (or a local ``.env`` file)
through Pydantic Settings. Nothing sensitive is hard-coded: the development
defaults below are intentionally non-secret and the application refuses to
start in ``production`` mode while they are still in use.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
DEFAULT_SQLITE_PATH: Path = PROJECT_ROOT / "data" / "gateway.db"

#: Placeholder secret used only for local development / demos.
INSECURE_DEV_SECRET = "dev-only-insecure-secret-change-me"

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Strongly-typed runtime configuration."""

    model_config = SettingsConfigDict(
        env_file=(str(PROJECT_ROOT / ".env"), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application -------------------------------------------------------
    app_name: str = "Enterprise AI Gateway & Compliance Proxy"
    app_version: str = "1.0.0"
    environment: Literal["development", "staging", "production", "test"] = "development"
    log_level: str = "INFO"

    # --- Persistence -------------------------------------------------------
    database_url: str = Field(default=f"sqlite+aiosqlite:///{DEFAULT_SQLITE_PATH}")
    redis_url: str | None = Field(default=None, description="Empty => in-memory rate limiter")
    redis_retry_interval_seconds: int = 30

    # --- Security ----------------------------------------------------------
    api_secret: str = Field(default=INSECURE_DEV_SECRET, min_length=16)
    trust_proxy_headers: bool = False
    cors_origins: str = "*"
    max_prompt_chars: int = 8000

    # --- Rate limiting -----------------------------------------------------
    rate_limit_tokens: int = Field(default=100, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)

    # --- Injection defense -------------------------------------------------
    injection_block_threshold: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"
    injection_rules_file: str | None = None

    # --- Mock LLM ----------------------------------------------------------
    mock_latency_scale: float = Field(default=1.0, ge=0.0, le=10.0)

    # --- Demo data ---------------------------------------------------------
    seed_demo_keys: bool = True
    auto_seed_demo_data: bool = True
    demo_transaction_count: int = Field(default=80, ge=0)

    # --- Paths -------------------------------------------------------------
    frontend_dir: Path = PROJECT_ROOT / "frontend"

    @field_validator("redis_url", "injection_rules_file", mode="before")
    @classmethod
    def _empty_to_none(cls, value: str | None) -> str | None:
        """Treat empty strings from ``.env`` files as *unset*."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("database_url", mode="before")
    @classmethod
    def _normalise_db_url(cls, value: str | None) -> str:
        """Upgrade sync driver URLs to their async equivalents."""
        if not value or not str(value).strip():
            return f"sqlite+aiosqlite:///{DEFAULT_SQLITE_PATH}"
        value = str(value).strip()
        if value.startswith("sqlite:///"):
            value = value.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
        elif value.startswith("mysql://"):
            value = value.replace("mysql://", "mysql+aiomysql://", 1)
        elif value.startswith("mysql+pymysql://"):
            value = value.replace("mysql+pymysql://", "mysql+aiomysql://", 1)
        return value

    @model_validator(mode="after")
    def _guard_production(self) -> "Settings":
        """Refuse insecure defaults in production."""
        if self.environment == "production" and self.api_secret == INSECURE_DEV_SECRET:
            raise ValueError("API_SECRET must be set to a strong random value in production")
        return self

    # --- Derived helpers ---------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()] or ["*"]


@lru_cache
def get_settings() -> Settings:
    """Return the cached settings singleton."""
    settings = Settings()
    if settings.api_secret == INSECURE_DEV_SECRET:
        logger.warning("Using the development API_SECRET. Set API_SECRET for any real deployment.")
    return settings

"""Application configuration.

All settings come from environment variables (optionally a backend/.env file).
Never hardcode secrets in code; SECRET_KEY must be provided by the environment.

Usage:
    from app.core.config import settings
    settings.database_url
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # backend/


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Security ---
    # Dev-only fallback (long enough to satisfy HS256); override in .env!
    secret_key: str = Field(
        default="dev-only-secret-do-not-use-in-production-0123456789abcdef",
        alias="SECRET_KEY",
    )
    access_token_expire_minutes: int = Field(default=1440, alias="ACCESS_TOKEN_EXPIRE_MINUTES")

    # --- Database ---
    database_url: str = Field(
        default="sqlite:///./sentinel.db", alias="DATABASE_URL"
    )

    # --- Uploads ---
    upload_dir: str = Field(default="uploads", alias="UPLOAD_DIR")
    max_upload_size: int = Field(
        default=10 * 1024 * 1024, alias="MAX_UPLOAD_SIZE"  # 10 MiB
    )

    # --- Scanner sandbox (Phase 2) ---
    sandbox_base_url: str = Field(default="http://localhost:9000", alias="SANDBOX_BASE_URL")
    scanner_base_url: str = Field(default="http://localhost:9100", alias="SCANNER_BASE_URL")

    # --- App ---
    environment: str = Field(default="development", alias="ENVIRONMENT")
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:5173", alias="CORS_ORIGINS"
    )
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    @field_validator("secret_key")
    @classmethod
    def warn_if_insecure_secret(cls, v: str) -> str:
        if v.startswith("dev-only") or len(v) < 32:
            import logging

            logging.getLogger(__name__).warning(
                "SECRET_KEY is missing or weak — set a long random value in .env "
                "before any non-local deployment."
            )
        return v

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def upload_path(self) -> Path:
        p = Path(self.upload_dir)
        return p if p.is_absolute() else (BASE_DIR / p).resolve()

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

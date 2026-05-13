from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = Field(default="GN Slop Detection", alias="APP_NAME")
    environment: str = Field(default="development", alias="ENVIRONMENT")
    slop_alert_threshold: float = Field(default=0.60, alias="SLOP_ALERT_THRESHOLD")
    web_fetch_timeout_seconds: float = Field(default=8.0, alias="WEB_FETCH_TIMEOUT_SECONDS")
    web_fetch_max_bytes: int = Field(default=1_048_576, alias="WEB_FETCH_MAX_BYTES")
    allow_private_urls: bool = Field(default=False, alias="ALLOW_PRIVATE_URLS")

    model_config = SettingsConfigDict(env_file=".env", populate_by_name=True, extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()

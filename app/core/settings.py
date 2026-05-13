from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = Field(default="GN Slop Detection", alias="APP_NAME")
    environment: str = Field(default="development", alias="ENVIRONMENT")
    slop_alert_threshold: float = Field(default=0.60, alias="SLOP_ALERT_THRESHOLD")

    model_config = SettingsConfigDict(env_file=".env", populate_by_name=True, extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()

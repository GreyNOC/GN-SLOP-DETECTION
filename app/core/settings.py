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
    rate_limit_requests: int = Field(default=120, alias="RATE_LIMIT_REQUESTS")
    rate_limit_window_seconds: float = Field(default=60.0, alias="RATE_LIMIT_WINDOW_SECONDS")
    rate_limit_enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")
    media_max_bytes: int = Field(default=64 * 1024 * 1024, alias="MEDIA_MAX_BYTES")
    # Hard cap applied by the body-cap middleware to every request body
    # before any route reads it. Default 256 MiB. Set to 0 to disable.
    max_request_body_bytes: int = Field(
        default=256 * 1024 * 1024, alias="MAX_REQUEST_BODY_BYTES"
    )
    # Optional containment for code scans. If set, code scan targets
    # are required to live underneath this base path (after symlink
    # resolution). Default empty = no containment, which is the right
    # behaviour for a local CLI / desktop install.
    code_scan_base_path: str = Field(default="", alias="CODE_SCAN_BASE_PATH")

    model_config = SettingsConfigDict(env_file=".env", populate_by_name=True, extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()

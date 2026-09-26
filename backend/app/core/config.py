"""Runtime configuration. Everything comes from environment variables / .env; nothing secret is hard-coded."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(REPO_ROOT / ".env"), str(BACKEND_DIR / ".env")),
        extra="ignore",
    )

    # --- core ---
    database_url: str = f"sqlite:///{(BACKEND_DIR / 'sentinelforge.db').as_posix()}"
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    api_key: SecretStr | None = None  # if set, every /api/v1 call except health/branding needs X-API-Key
    rate_limit_per_minute: int = 1200
    max_batch_events: int = 20000

    # --- rules / plugins ---
    # "builtin" = the rule packs shipped with the sentinelforge library
    rule_paths: str = f"builtin,{(REPO_ROOT / 'custom-rules').as_posix()}"
    plugin_paths: str = ""  # comma-separated directories containing plugin packages
    plugins: str = ""  # comma-separated plugin module names to load from plugin_paths
    auto_activate_rules: bool = True
    store_unmatched_events: bool = True

    # --- discovery ---
    enable_live_discovery: bool = False  # running PowerShell from the API is opt-in
    discovery_timeout_seconds: int = 180

    # --- SIEM ---
    siem_mode: Literal["disabled", "webhook", "splunk", "elastic"] | str = "disabled"
    siem_timeout_seconds: float = 5.0
    webhook_url: str = ""
    webhook_auth_header: SecretStr | None = None
    splunk_hec_url: str = ""
    splunk_hec_token: SecretStr | None = None
    splunk_index: str = ""
    splunk_source: str = "sentinelforge"
    splunk_verify_tls: bool = True
    elastic_url: str = ""
    elastic_api_key: SecretStr | None = None
    elastic_index: str = "sentinelforge-detections"
    elastic_verify_tls: bool = True

    # --- branding (attribution to the upstream project is kept separately, see api/routes/about.py) ---
    project_name: str = "SentinelForge"
    project_description: str = "Agentless Environment-Aware Detection Engineering Platform"
    organization_name: str = ""
    organization_logo: str = ""  # URL or /path served by the frontend
    primary_brand_color: str = "#38bdf8"
    dashboard_title: str = "Detection Operations"
    footer_text: str = ""

    def split(self, value: str) -> list[str]:
        return [v.strip() for v in value.split(",") if v.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

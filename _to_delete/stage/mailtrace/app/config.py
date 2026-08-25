"""Settings. Everything env-driven so the demo laptop and CI agree."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # FIXTURE_MODE=1 serves fixtures/*.json with no DB and no network.
    # Track F builds the entire dashboard against this.
    fixture_mode: bool = True
    log_level: str = "INFO"

    database_url: str = "postgresql+psycopg://mailtrace:mailtrace@localhost:5432/mailtrace"
    redis_url: str = "redis://localhost:6379/0"

    # Trust boundary (M2). Comma-separated in .env.
    trusted_mx_hosts: str = ""
    trusted_mx_cidrs: str = ""
    trusted_providers: str = ""

    intel_dir: str = "./intel"
    maxmind_account_id: str = ""
    maxmind_license_key: str = ""
    ipinfo_token: str = ""
    abuseipdb_key: str = ""
    virustotal_key: str = ""
    urlscan_key: str = ""

    llm_api_key: str = ""
    llm_model: str = ""

    @property
    def trusted_hosts(self) -> set[str]:
        return {h.strip().lower() for h in self.trusted_mx_hosts.split(",") if h.strip()}

    @property
    def trusted_cidrs(self) -> list[str]:
        return [c.strip() for c in self.trusted_mx_cidrs.split(",") if c.strip()]

    @property
    def providers(self) -> set[str]:
        return {p.strip().lower() for p in self.trusted_providers.split(",") if p.strip()}


@lru_cache(maxsize=1)
def settings() -> Settings:
    return Settings()

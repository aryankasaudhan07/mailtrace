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

    # Trust boundary (M2). Comma-separated in .env. DEPLOYMENTS MUST OVERRIDE
    # these with their own receiving infrastructure. The default names the
    # fixture/demo MX so the boundary resolves out-of-the-box in fixture mode;
    # in production set TRUSTED_MX_HOSTS / TRUSTED_MX_CIDRS to your real MX.
    trusted_mx_hosts: str = "mx.example.ac.in"
    trusted_mx_cidrs: str = ""
    trusted_providers: str = ""

    # OTP email delivery. Two transports, tried in this order:
    #  1) Brevo HTTP API (port 443) -- works on hosts that block outbound SMTP,
    #     e.g. Render's free tier. Set brevo_api_key + mail_from (a Brevo-verified
    #     sender). This is the recommended path for the cloud deploy.
    #  2) SMTP -- for hosts that allow it. Gmail: smtp_user = your address,
    #     smtp_password = a Google App Password (needs 2FA).
    # With neither set, the flow falls back to showing the code in-UI (demo mode).
    brevo_api_key: str = ""
    mail_from: str = ""            # verified sender address (Brevo or SMTP "From")
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""            # legacy alias for mail_from

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

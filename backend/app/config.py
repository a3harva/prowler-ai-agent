"""Config resolves once at startup into a cached Settings singleton.

No per-request or per-task fetches. Every key listed in .env.sample must be
present in the resolved backend or startup fails, naming every missing key —
including keys not yet used by any feature, so a stray deletion is caught
immediately rather than surfacing as a confusing None much later.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from app.secrets import EnvFileProvider, MissingSecretError, SecretManagerProvider, SecretProvider

# Mirrors .env.sample exactly. Update both together.
CONFIG_KEYS = [
    "POSTGRES_USER",
    "POSTGRES_DB",
    "POSTGRES_PASSWORD",
    "DATABASE_URL",
    "TEST_DATABASE_URL",
    "REDIS_URL",
    "DOCKER_HOST",
    "PROWLER_IMAGE",
    "REPORTS_PATH",
    "HOST_REPORTS_PATH",
    "MAX_CONCURRENT_SCANS",
    "SCAN_TIMEOUT_SECONDS",
    "GCLOUD_ADC_PATH",
    "GOOGLE_OAUTH_CLIENT_ID",
    "GOOGLE_OAUTH_CLIENT_SECRET",
    "OAUTH_REDIRECT_URI",
    "FRONTEND_ORIGIN",
    "ALLOWED_HOSTS",
    "ENABLE_API_DOCS",
    "JWT_SIGNING_KEY",
    "ACCESS_TOKEN_TTL_MINUTES",
    "REFRESH_TOKEN_TTL_DAYS",
    "ALLOWED_EMAIL_DOMAIN",
    "BOOTSTRAP_ADMIN_EMAILS",
    "FRESHSERVICE_DOMAIN",
    "FRESHSERVICE_API_KEY",
    "GCP_PROJECT_ID",
    "GEMINI_PROJECT_ID",
    "GEMINI_SERVICE_ACCOUNT",
    "GEMINI_LOCATION",
    "GEMINI_MODEL",
    "GEMINI_MAX_OUTPUT_TOKENS",
    # Separate from GEMINI_MODEL on purpose. The report path is one long
    # single-shot generation; the agent is many short tool-calling turns.
    # They want different models and different ceilings, and tuning the
    # agent must not silently retune a customer-facing report.
    "GEMINI_AGENT_MODEL",
    "GEMINI_AGENT_MAX_OUTPUT_TOKENS",
    # Agent observability. The two keys are deliberately allowed to be empty —
    # empty means "no tracing", resolved to a no-op client, the same convention
    # GEMINI_SERVICE_ACCOUNT uses. They must still be *present*: this list is
    # what turns a deleted line into a startup failure instead of a confusing
    # None much later, and that guarantee is worth more than the convenience of
    # omitting a key that has no value yet.
    "LANGFUSE_PUBLIC_KEY",
    "LANGFUSE_SECRET_KEY",
    "LANGFUSE_HOST",
    # Live cloud context — the report agent's read-only gcloud/bq access.
    "CLOUD_CLI_IMAGE",
    "CLOUD_CLI_ENABLED",
    "MAX_CONCURRENT_CLI_SESSIONS",
    # Separate from MAX_CONCURRENT_SCANS since the worker split: reports and
    # scans get their own process and their own queue, so neither number is
    # derivable from the other any more.
    "MAX_CONCURRENT_REPORTS",
    "VITE_API_BASE_URL",
]


@dataclass(frozen=True)
class Settings:
    app_env: str
    values: dict[str, str]

    def __getitem__(self, key: str) -> str:
        return self.values[key]

    @property
    def database_url(self) -> str:
        return self.values["DATABASE_URL"]

    @property
    def test_database_url(self) -> str:
        return self.values["TEST_DATABASE_URL"]

    @property
    def redis_url(self) -> str:
        return self.values["REDIS_URL"]


def _build_provider(app_env: str) -> SecretProvider:
    if app_env == "local":
        env_local_path = os.environ.get("ENV_LOCAL_PATH", "/app/.env.local")
        return EnvFileProvider(env_local_path)
    # GCP_PROJECT_ID is the one key that must come from the process environment
    # directly — Secret Manager cannot be reached without it first.
    gcp_project_id = os.environ.get("GCP_PROJECT_ID")
    if not gcp_project_id:
        raise RuntimeError(
            "GCP_PROJECT_ID must be set in the process environment when APP_ENV != local"
        )
    return SecretManagerProvider(gcp_project_id)


def load_settings() -> Settings:
    app_env = os.environ.get("APP_ENV", "local")
    provider = _build_provider(app_env)

    values: dict[str, str] = {}
    missing: list[str] = []
    for key in CONFIG_KEYS:
        try:
            values[key] = provider.get(key)
        except MissingSecretError:
            missing.append(key)

    if missing:
        raise RuntimeError(
            "startup aborted, missing required configuration keys: " + ", ".join(missing)
        )

    return Settings(app_env=app_env, values=values)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings

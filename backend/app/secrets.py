"""Two config backends, selected by APP_ENV. See AGENTS.md § Working conventions."""

from __future__ import annotations

import os
from typing import Protocol


class MissingSecretError(RuntimeError):
    def __init__(self, key: str, source: str):
        super().__init__(f"missing required configuration key '{key}' (source: {source})")
        self.key = key


class SecretProvider(Protocol):
    def get(self, key: str) -> str: ...


class EnvFileProvider:
    """APP_ENV=local — reads KEY=VALUE pairs from .env.local. Never used otherwise."""

    def __init__(self, path: str):
        self._path = path
        if not os.path.isfile(path):
            raise FileNotFoundError(f"local env file not found: {path}")
        self._values: dict[str, str] = {}
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                self._values[key.strip()] = value.strip()

    def get(self, key: str) -> str:
        if key not in self._values:
            raise MissingSecretError(key, os.path.basename(self._path))
        return self._values[key]


class SecretManagerProvider:
    """Anything other than APP_ENV=local — reads from GCP Secret Manager via ADC."""

    def __init__(self, gcp_project_id: str):
        from google.cloud import secretmanager

        self._client = secretmanager.SecretManagerServiceClient()
        self._project_id = gcp_project_id
        self._cache: dict[str, str] = {}

    def get(self, key: str) -> str:
        if key in self._cache:
            return self._cache[key]
        name = f"projects/{self._project_id}/secrets/{key}/versions/latest"
        try:
            response = self._client.access_secret_version(name=name)
        except Exception as exc:  # noqa: BLE001 - any backend failure means "missing"
            raise MissingSecretError(key, "Secret Manager") from exc
        value = response.payload.data.decode("utf-8")
        self._cache[key] = value
        return value

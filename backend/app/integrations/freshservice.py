"""Freshservice is the system of record for departments. There is deliberately
no free-text fallback here — anything this client can't confirm must refuse,
not degrade into a locally-typed department that silently drifts from
Freshservice.
"""

from __future__ import annotations

import requests

from app.services.errors import ServiceError


class FreshserviceError(ServiceError):
    """Base for every failure this client can raise. Defaults to 502: anything
    from a third-party system that is not specifically our caller's fault is an
    upstream problem, not a bad request."""

    status_code = 502


class FreshserviceNotFoundError(FreshserviceError):
    """The one case that *is* about the caller's input — they named a
    department id Freshservice does not have."""

    status_code = 404

    def __init__(self, freshservice_id: str):
        super().__init__(f"no Freshservice department found for id '{freshservice_id}'")
        self.freshservice_id = freshservice_id


class FreshserviceUnavailableError(FreshserviceError):
    """Network failure, timeout, bad credentials, or any non-2xx/404 response."""


class FreshserviceDepartment:
    def __init__(self, *, freshservice_id: str, name: str, domains: list[str]):
        self.freshservice_id = freshservice_id
        self.name = name
        self.domains = domains


def fetch_department(
    freshservice_id: str, *, domain: str, api_key: str, timeout: float = 10.0
) -> FreshserviceDepartment:
    url = f"https://{domain}.freshservice.com/api/v2/departments/{freshservice_id}"
    try:
        response = requests.get(url, auth=(api_key, "X"), timeout=timeout)
    except requests.RequestException as exc:
        raise FreshserviceUnavailableError(f"Freshservice request failed: {exc}") from exc

    if response.status_code == 404:
        raise FreshserviceNotFoundError(freshservice_id)
    if not response.ok:
        raise FreshserviceUnavailableError(
            f"Freshservice returned {response.status_code} for department '{freshservice_id}'"
        )

    try:
        payload = response.json()["department"]
    except (ValueError, KeyError) as exc:
        raise FreshserviceUnavailableError("Freshservice returned an unexpected response shape") from exc

    return FreshserviceDepartment(
        freshservice_id=str(payload["id"]),
        name=payload["name"],
        domains=payload.get("domains") or [],
    )

"""The application's own session tokens — separate from Google's ID token,
which is only ever used at the moment of sign-in. Short access lifetime is
deliberate: it bounds how long a revoked user keeps working.
"""

from __future__ import annotations

import datetime

import jwt

from app.config import Settings

ALGORITHM = "HS256"


class TokenError(RuntimeError):
    pass


def _encode(*, payload: dict, ttl: datetime.timedelta, signing_key: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    full_payload = {**payload, "iat": now, "exp": now + ttl}
    return jwt.encode(full_payload, signing_key, algorithm=ALGORITHM)


def create_access_token(*, user_id: int, email: str, settings: Settings) -> str:
    ttl = datetime.timedelta(minutes=int(settings["ACCESS_TOKEN_TTL_MINUTES"]))
    return _encode(
        payload={"sub": str(user_id), "email": email, "type": "access"},
        ttl=ttl,
        signing_key=settings["JWT_SIGNING_KEY"],
    )


def create_refresh_token(*, user_id: int, settings: Settings) -> str:
    ttl = datetime.timedelta(days=int(settings["REFRESH_TOKEN_TTL_DAYS"]))
    return _encode(
        payload={"sub": str(user_id), "type": "refresh"},
        ttl=ttl,
        signing_key=settings["JWT_SIGNING_KEY"],
    )


def decode_token(token: str, *, expected_type: str, settings: Settings) -> dict:
    try:
        payload = jwt.decode(token, settings["JWT_SIGNING_KEY"], algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    if payload.get("type") != expected_type:
        raise TokenError(f"expected a {expected_type} token")
    return payload

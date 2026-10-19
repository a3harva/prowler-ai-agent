from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.auth.tokens import TokenError, create_access_token, create_refresh_token, decode_token
from app.config import Settings, get_settings
from app.db import get_db
from app.models.user import User

ACCESS_COOKIE_NAME = "access_token"
REFRESH_COOKIE_NAME = "refresh_token"


def cookie_kwargs(settings: Settings) -> dict:
    # secure=False locally so the cookie survives over plain http://localhost;
    # every non-local APP_ENV serves over TLS and gets secure=True.
    return {
        "httponly": True,
        "secure": settings.app_env != "local",
        "samesite": "lax",
    }


def issue_session_cookies(response: Response, *, user: User, settings: Settings) -> None:
    """The one place any login path (Google callback, password login) calls
    to become "signed in" — mints both tokens and sets both cookies, so
    there is exactly one definition of what a session looks like.
    """
    access_token = create_access_token(user_id=user.id, email=user.email, settings=settings)
    refresh_token = create_refresh_token(user_id=user.id, settings=settings)
    response.set_cookie(
        ACCESS_COOKIE_NAME,
        access_token,
        max_age=int(settings["ACCESS_TOKEN_TTL_MINUTES"]) * 60,
        **cookie_kwargs(settings),
    )
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        refresh_token,
        max_age=int(settings["REFRESH_TOKEN_TTL_DAYS"]) * 86400,
        **cookie_kwargs(settings),
    )


@dataclass
class CurrentUser:
    user: User
    is_bootstrap_admin: bool


def bootstrap_admin_emails(settings: Settings) -> set[str]:
    raw = settings["BOOTSTRAP_ADMIN_EMAILS"]
    return {email.strip().lower() for email in raw.split(",") if email.strip()}


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> CurrentUser:
    token = request.cookies.get(ACCESS_COOKIE_NAME)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    try:
        payload = decode_token(token, expected_type="access", settings=settings)
    except TokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired session")
    user = db.get(User, int(payload["sub"]))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user no longer exists")
    is_admin = user.email.lower() in bootstrap_admin_emails(settings)
    return CurrentUser(user=user, is_bootstrap_admin=is_admin)


def require_admin(current: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    # Bootstrap-list membership is the global admin grant; department roles
    # are additive and do not change this check's meaning.
    if not current.is_bootstrap_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin privileges required")
    return current

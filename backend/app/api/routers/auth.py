import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import (
    ACCESS_COOKIE_NAME,
    REFRESH_COOKIE_NAME,
    CurrentUser,
    cookie_kwargs,
    get_current_user,
    issue_session_cookies,
)
from app.auth.domain_gate import DomainNotAllowedError, check_hosted_domain, is_email_domain_allowed
from app.auth.passwords import verify_password
from app.auth.tokens import TokenError, create_access_token, decode_token
from app.config import Settings, get_settings
from app.db import get_db
from app.integrations.google_oauth import (
    GoogleOAuthError,
    build_authorization_url,
    exchange_code_for_id_token,
    verify_id_token,
)
from app.models.user import User
from app.models.user_department_role import UserDepartmentRole
from app.schemas.auth import LocalLoginRequest
from app.schemas.user import CurrentUserResponse, DepartmentGrantResponse
from app.services.rate_limit import check_and_increment_login_attempts
from app.services.users import upsert_user_from_login

router = APIRouter(prefix="/api/auth", tags=["auth"])

STATE_COOKIE_NAME = "oauth_state"


@router.get("/login")
def login(request: Request, settings: Settings = Depends(get_settings)):
    state = secrets.token_urlsafe(32)
    url = build_authorization_url(
        client_id=settings["GOOGLE_OAUTH_CLIENT_ID"],
        redirect_uri=settings["OAUTH_REDIRECT_URI"],
        state=state,
        hosted_domain_hint=settings["ALLOWED_EMAIL_DOMAIN"],
    )
    response = RedirectResponse(url=url)
    response.set_cookie(STATE_COOKIE_NAME, state, max_age=600, **cookie_kwargs(settings))
    return response


@router.get("/callback")
def callback(
    request: Request,
    code: str,
    state: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    expected_state = request.cookies.get(STATE_COOKIE_NAME)
    if not expected_state or not secrets.compare_digest(state, expected_state):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired sign-in attempt")

    try:
        id_token_str = exchange_code_for_id_token(
            code=code,
            client_id=settings["GOOGLE_OAUTH_CLIENT_ID"],
            client_secret=settings["GOOGLE_OAUTH_CLIENT_SECRET"],
            redirect_uri=settings["OAUTH_REDIRECT_URI"],
        )
        claims = verify_id_token(id_token_str, client_id=settings["GOOGLE_OAUTH_CLIENT_ID"])
    except GoogleOAuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"sign-in failed: {exc}") from exc

    try:
        # Gate on the verified claim only — the `hd` hint sent in /login is
        # never consulted here, so it cannot be used to bypass this check.
        check_hosted_domain(claims, allowed_domain=settings["ALLOWED_EMAIL_DOMAIN"])
    except DomainNotAllowedError as exc:
        response = RedirectResponse(url=f"{settings['FRONTEND_ORIGIN']}/login?login_error=domain_not_allowed")
        response.delete_cookie(STATE_COOKIE_NAME)
        return response

    user = upsert_user_from_login(db, email=claims["email"], name=claims.get("name", claims["email"]))

    response = RedirectResponse(url=settings["FRONTEND_ORIGIN"])
    response.delete_cookie(STATE_COOKIE_NAME)
    issue_session_cookies(response, user=user, settings=settings)
    return response


@router.post("/refresh")
def refresh(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no refresh session")
    try:
        payload = decode_token(token, expected_type="refresh", settings=settings)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh session expired") from exc

    # The refresh token carries no email — deliberately minimal, since a
    # refresh should not need to re-touch the user table.
    user = db.get(User, int(payload["sub"]))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user no longer exists")
    access_token = create_access_token(user_id=user.id, email=user.email, settings=settings)

    response = JSONResponse({"status": "ok"})
    response.set_cookie(
        ACCESS_COOKIE_NAME,
        access_token,
        max_age=int(settings["ACCESS_TOKEN_TTL_MINUTES"]) * 60,
        **cookie_kwargs(settings),
    )
    return response


@router.post("/login-local")
def login_local(
    body: LocalLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    client_ip = request.client.host if request.client else "unknown"
    if not check_and_increment_login_attempts(ip=client_ip, email=body.email, settings=settings):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts, try again later")

    email = body.email.strip().lower()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is None or user.password_hash is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid email or password")

    # Defense in depth: re-check even though an admin-created account should
    # already comply — catches a since-narrowed ALLOWED_EMAIL_DOMAIN.
    if not is_email_domain_allowed(user.email, allowed_domain=settings["ALLOWED_EMAIL_DOMAIN"]):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "account domain not allowed")

    user.last_login_at = func.now()
    db.commit()

    response = JSONResponse({"status": "ok"})
    issue_session_cookies(response, user=user, settings=settings)
    return response


@router.post("/logout")
def logout():
    response = JSONResponse({"status": "ok"})
    response.delete_cookie(ACCESS_COOKIE_NAME)
    response.delete_cookie(REFRESH_COOKIE_NAME)
    return response


@router.get("/me", response_model=CurrentUserResponse)
def me(
    current: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    grants = db.execute(
        select(UserDepartmentRole).where(UserDepartmentRole.user_id == current.user.id)
    ).scalars()
    return CurrentUserResponse(
        email=current.user.email,
        name=current.user.name,
        is_bootstrap_admin=current.is_bootstrap_admin,
        grants=[DepartmentGrantResponse.model_validate(g) for g in grants],
    )

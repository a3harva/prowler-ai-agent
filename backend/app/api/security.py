"""Transport-level security controls for the API.

Installed once from ``app.api.main``. Deliberately free of any ``app.*`` import
so the middleware can be unit tested against a throwaway Starlette app without
the full application (and its WeasyPrint/Pango native dependency) being
importable.

What lives here:

* security response headers (nosniff, frame denial, referrer policy, and — on
  a TLS deployment — CSP and HSTS),
* a coarse request-body ceiling,
* a cross-origin guard for cookie-authenticated mutations,
* trusted-host filtering.

The cross-origin guard is not a replacement for a CSRF token: it rejects a
browser request whose ``Origin`` header names a different site than the request
``Host`` or the configured frontend origin. Non-browser clients (which send no
``Origin``) are unaffected. A follow-up should add a synchronizer/double-submit
token for the cookie-authenticated mutations this cannot cover.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024

_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    "font-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def security_headers(*, tls: bool) -> dict[str, str]:
    """The header set applied to every API response.

    CSP and HSTS are only sent on a TLS deployment. In local development the
    frontend is served by Vite with websocket HMR and inline bootstrap scripts,
    and an HSTS header over plain ``http://localhost`` would poison the
    developer's browser for other local projects.
    """
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }
    if tls:
        headers["Content-Security-Policy"] = _CSP
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return headers


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        tls: bool,
        allowed_origins: Iterable[str] = (),
        max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES,
    ) -> None:
        super().__init__(app)
        self._tls = tls
        self._allowed_origins = {origin.rstrip("/") for origin in allowed_origins if origin}
        self._max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        rejection = self._reject_oversized(request)
        if rejection is not None:
            return rejection
        if request.method in _UNSAFE_METHODS:
            origin = request.headers.get("origin")
            if origin and not self._origin_allowed(request, origin):
                return JSONResponse({"detail": "cross-origin request rejected"}, status_code=403)

        response = await call_next(request)
        for name, value in security_headers(tls=self._tls).items():
            response.headers.setdefault(name, value)
        return response

    def _reject_oversized(self, request: Request) -> JSONResponse | None:
        raw_length = request.headers.get("content-length")
        if raw_length is None:
            return None
        try:
            length = int(raw_length)
        except ValueError:
            return JSONResponse({"detail": "invalid content length"}, status_code=400)
        if length > self._max_body_bytes:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        return None

    def _origin_allowed(self, request: Request, origin: str) -> bool:
        if origin.rstrip("/") in self._allowed_origins:
            return True
        host = request.headers.get("host")
        return bool(host) and urlsplit(origin).netloc == host


def install_security_middleware(
    app,
    *,
    tls: bool,
    frontend_origin: str = "",
    allowed_hosts: Iterable[str] = (),
) -> None:
    """Attach the controls above to a Starlette/FastAPI application.

    Trusted-host filtering is only attached when a list is supplied; an empty
    list means "no opinion", which keeps the local development stack and the
    test client working while production supplies an explicit list.
    """
    hosts = [host.strip() for host in allowed_hosts if host and host.strip()]
    if tls and hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
    app.add_middleware(
        SecurityMiddleware,
        tls=tls,
        allowed_origins=[frontend_origin] if frontend_origin else [],
    )
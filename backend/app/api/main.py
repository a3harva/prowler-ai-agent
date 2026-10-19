from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.routers.agent import router as agent_router
from app.api.routers.audit import router as audit_router
from app.api.routers.auth import router as auth_router
from app.api.routers.compliance import router as compliance_router
from app.api.routers.departments import router as departments_router
from app.api.routers.findings import router as findings_router
from app.api.routers.organizations import router as organizations_router
from app.api.routers.projects import router as projects_router
from app.api.routers.reports import router as reports_router
from app.api.routers.scans import router as scans_router
from app.api.routers.users import router as users_router
from app.api.security import install_security_middleware
from app.config import get_settings
from app.logging_config import configure_logging
from app.services.errors import ServiceError

# At import, not in `lifespan`, so a log line emitted while the routers above
# are still being imported is not lost. Uvicorn leaves the root logger
# untouched, so without this the API process discards every app `logger.info`
# — including `gemini_agent`'s per-call model/latency/token lines, and the chat
# agent runs here. See `app/logging_config.py`; the worker needs none of this
# because Celery configures root itself.
configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Forces config resolution at process startup, not on first request —
    # a missing key must fail loudly before the app ever answers traffic.
    get_settings()
    yield


# Resolved at import so the middleware stack can be configured before the app
# starts serving. The lifespan call above still re-checks at startup.
_settings = get_settings()
_is_local = _settings.app_env == "local"
_docs_enabled = _is_local or _settings["ENABLE_API_DOCS"].strip().lower() == "true"

app = FastAPI(
    title="prowler agent",
    lifespan=lifespan,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

install_security_middleware(
    app,
    tls=not _is_local,
    frontend_origin=_settings["FRONTEND_ORIGIN"],
    allowed_hosts=_settings["ALLOWED_HOSTS"].split(","),
)


@app.exception_handler(ServiceError)
async def service_error_handler(request: Request, exc: ServiceError) -> JSONResponse:
    """The single translation from a service-layer error to an HTTP response.

    This replaced thirty-one hand-written `except ... raise HTTPException`
    blocks across seven routers. Each one did exactly this, and each one was a
    place to answer 404 where the endpoint next door answered 409, or to catch
    a same-named class imported from the wrong module and answer 500 instead.
    The status now travels on the exception (see `services/errors.py`), so a
    new error type needs no router change.

    `detail` keeps the same shape FastAPI's own HTTPException produces, so
    nothing on the frontend had to change — `errorMessage()` in
    `api/client.ts` reads `detail` and still finds it.
    """
    return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})


app.include_router(agent_router)
app.include_router(audit_router)
app.include_router(auth_router)
app.include_router(compliance_router)
app.include_router(departments_router)
app.include_router(findings_router)
app.include_router(organizations_router)
app.include_router(projects_router)
app.include_router(reports_router)
app.include_router(scans_router)
app.include_router(users_router)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

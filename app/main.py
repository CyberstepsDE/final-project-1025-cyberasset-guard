"""CyberAsset Guard — FastAPI application entrypoint.

Run with:  uvicorn app.main:app            (add --reload only for local development)
UI at:     http://127.0.0.1:8000/
Docs at:   http://127.0.0.1:8000/docs
Health:    /health/live (liveness), /health/ready (readiness incl. database)

Everything except the web UI shell, static files, health checks, API docs and
/auth/login|status requires a logged-in user; permissions come from the user's role.
"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import SQLAlchemyError

from . import __version__, config, database
from .assets.routes import router as assets_router
from .audit import service as audit
from .audit.models import Outcome
from .audit.routes import router as audit_router
from .auth.dependencies import anonymous_context, require_by_method
from .auth.permissions import Permission
from .auth.routes import auth_router, users_router
from .auth.service import count_users
from .correlation import jobs as correlation_jobs
from .correlation.routes import router as correlation_router
from .dashboard.routes import router as dashboard_router
from .logging_config import setup_logging
from .monitoring import scheduler
from .monitoring.routes import router as monitoring_router
from .risk.routes import router as risk_router
from .ticketing import jobs as ticketing_jobs
from .ticketing.routes import router as ticketing_router

log = setup_logging(config.LOG_LEVEL).getChild("main")
WEB_DIR = Path(__file__).resolve().parent / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db_path = database.describe()                       # file path or URL with masked password
    log.info("starting CyberAsset Guard %s (database: %s)", __version__, db_path)
    try:
        sqlite_file = database.sqlite_path()
        config.validate_runtime(sqlite_file, check_db_path=sqlite_file is not None)
        database.ensure_schema()   # apply Alembic migrations to head (auto-upgrade on startup)
    except config.ConfigError as exc:
        log.critical("startup aborted - configuration problem: %s", exc)
        raise
    except Exception:
        log.critical("startup aborted - database at %s could not be initialized", db_path,
                     exc_info=True)
        raise
    scheduler.start()              # Monitoring Part 4: resume persisted scan schedules
    correlation_jobs.on_startup()                          # runs interrupted by a restart -> failed
    correlation_jobs.register(scheduler.get_scheduler())   # periodic NVD/KEV refresh + re-correlation
    ticketing_jobs.register(scheduler.get_scheduler())     # Jira delivery worker (if CAG_JIRA_ENABLED)
    if config.BACKUP_INTERVAL_HOURS > 0 and database.dialect() != "sqlite":
        log.info("scheduled file backups skipped: the database server is backed up by its provider "
                 "(Azure PostgreSQL automated backups)")
    elif config.BACKUP_INTERVAL_HOURS > 0:
        from datetime import datetime, timedelta

        from .maintenance import scheduled_backup
        scheduler.get_scheduler().add_job(
            scheduled_backup, trigger="interval", hours=config.BACKUP_INTERVAL_HOURS, id="cag-backup",
            replace_existing=True, next_run_time=datetime.now() + timedelta(minutes=5))
        log.info("scheduled backups every %dh to %s (keep %d daily / %d weekly)", config.BACKUP_INTERVAL_HOURS,
                 config.BACKUP_DIR, config.BACKUP_KEEP_DAILY, config.BACKUP_KEEP_WEEKLY)
    with next(database.get_session()) as session:
        if count_users(session) == 0:
            log.warning("no user accounts exist yet - create an administrator with: "
                        "python -m app.maintenance create-user <username> --role admin")
    log.info("startup complete")
    try:
        yield
    finally:
        scheduler.shutdown()
        database.get_engine().dispose()
        log.info("shutdown complete")


app = FastAPI(
    title="CyberAsset Guard",
    description="Asset-centric cybersecurity platform (MVP): Asset Management, Monitoring and "
                "vulnerability correlation (NVD, CISA KEV).",
    version=__version__,
    lifespan=lifespan,
    debug=False,                   # never return tracebacks to clients
)


@app.exception_handler(SQLAlchemyError)
async def database_error(request: Request, exc: SQLAlchemyError):
    """Log the details server-side; never leak SQL or stack traces to clients."""
    log.error("database error on %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(status_code=500,
                        content={"detail": "A database error occurred. Please try again later."})


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    log.error("unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
NO_STORE_PREFIXES = ("/auth", "/users", "/audit", "/assets", "/monitoring", "/findings", "/correlation",
                     "/integrations")
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def _origin_allowed(request: Request) -> bool:
    """CSRF defence in depth (besides SameSite=Strict cookies): state-changing
    requests sent by a browser must come from our own origin."""
    own = f"{request.url.scheme}://{request.headers.get('host', '')}"
    allowed = {own, *config.TRUSTED_ORIGINS}
    origin = request.headers.get("origin")
    if origin is not None:
        return origin.rstrip("/") in allowed
    referer = request.headers.get("referer")
    if referer is not None:
        return any(referer == o or referer.startswith(o + "/") for o in allowed)
    return True        # non-browser clients (curl, scripts) send neither header


def _monitoring_action(method: str, path: str) -> str:
    parts = [p for p in path.split("/") if p]          # ["monitoring", "schedules", "3"]
    name = parts[1] if len(parts) > 1 else "request"
    if "schedules" in parts:                           # /monitoring/schedules/* or /monitoring/assets/{id}/schedules
        return "monitoring.schedule_delete" if method == "DELETE" else "monitoring.schedule_create"
    if parts[-1:] == ["scan"]:                         # /monitoring/assets/{id}/scan
        return "monitoring.scan"
    return f"monitoring.{name}"


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    method, path = request.method, request.url.path
    if method in UNSAFE_METHODS and not _origin_allowed(request):
        audit.record_now(anonymous_context(request), "access.csrf_rejected", outcome=Outcome.DENIED,
                         details={"method": method, "path": path,
                                  "origin": request.headers.get("origin") or request.headers.get("referer")})
        return JSONResponse(status_code=403, content={"detail": "Cross-origin request rejected"})

    response = await call_next(request)

    # The Monitoring routes don't record audit events themselves, so audit their
    # state-changing calls here. Denials (403) are already logged by the auth layer.
    ctx = getattr(request.state, "audit_ctx", None)
    if path.startswith("/monitoring/") and method in UNSAFE_METHODS and ctx and response.status_code not in (401, 403):
        audit.record_now(ctx, _monitoring_action(method, path),
                         outcome=Outcome.SUCCESS if response.status_code < 400 else Outcome.FAILURE,
                         target_type="monitoring", target_id=path.rsplit("/", 1)[-1][:64],
                         details={"method": method, "path": path, "status": response.status_code})

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if not path.startswith(("/docs", "/redoc")):     # Swagger UI loads its assets from a CDN
        response.headers.setdefault("Content-Security-Policy", CSP)
    if path.startswith(NO_STORE_PREFIXES):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


app.include_router(auth_router)
app.include_router(users_router)
app.include_router(audit_router)
app.include_router(assets_router)
app.include_router(correlation_router)
app.include_router(risk_router)
app.include_router(ticketing_router)
app.include_router(dashboard_router)
app.include_router(monitoring_router,
                   dependencies=[Depends(require_by_method(Permission.MONITORING_READ,
                                                           Permission.MONITORING_RUN))])
app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")


@app.get("/", include_in_schema=False)
def web_ui():
    """Asset Management web interface (single page, served by FastAPI)."""
    return FileResponse(WEB_DIR / "index.html")


@app.get("/health", tags=["health"])
@app.get("/health/live", tags=["health"])
def liveness():
    """Liveness: the process is up and serving requests. No dependency checks."""
    return {"status": "ok"}


@app.get("/health/ready", tags=["health"],
         responses={503: {"description": "A dependency (database) is not available"}})
def readiness():
    """Readiness: the database is reachable and its schema exists.
    Deliberately reveals no paths, versions or error details."""
    if database.check_ready():
        return {"status": "ready", "checks": {"database": "ok"}}
    return JSONResponse(status_code=503,
                        content={"status": "not_ready", "checks": {"database": "unavailable"}})

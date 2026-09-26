"""SentinelForge API. Run: uvicorn app.main:app --reload   (from backend/)"""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.routes import about, dashboard, demo, detections, discovery, environments, events, rules, siem
from app.core.config import get_settings
from app.core.logging import get_logger, setup_logging
from app.core.security import RateLimiter, require_api_key
from app.db.session import SessionLocal, init_db
from app.plugins import load_plugins
import sentinelforge.normalize  # noqa: F401  (registers built-in parsers)
from app.services.rules import sync_rule_store
from app.services.siem import gateway  # noqa: F401  (registers built-in SIEM adapters)

MAX_BODY_BYTES = 60 * 1024 * 1024
log = get_logger("api")


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    setup_logging(settings.log_level)
    init_db()
    load_plugins()
    with SessionLocal() as db:
        sync_rule_store(db)
    log.info("api.started", version=__version__, siem_mode=settings.siem_mode, auth=bool(settings.api_key))
    yield


app = FastAPI(
    title="SentinelForge API",
    version=__version__,
    description="Agentless environment-aware detection engineering platform. Originally created by Sujhal Gurav. Apache-2.0.",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

settings = get_settings()
app.add_middleware(CORSMiddleware, allow_origins=settings.split(settings.cors_origins), allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH"], allow_headers=["Content-Type", "X-API-Key"])
limiter = RateLimiter(settings.rate_limit_per_minute)


@app.middleware("http")
async def guard(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "request body too large"}, status_code=413)
    if request.url.path.startswith("/api/v1"):
        try:
            limiter.check(request)
        except Exception as e:  # HTTPException from limiter
            return JSONResponse({"detail": getattr(e, "detail", "rate limited")}, status_code=429)
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def validation_handler(_: Request, exc: RequestValidationError):
    # Don't echo large request bodies back; field locations and messages are enough.
    return JSONResponse({"detail": [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()[:20]]}, status_code=422)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.error("api.unhandled_error", path=request.url.path, error=type(exc).__name__)
    return JSONResponse({"detail": "internal error"}, status_code=500)


@app.get("/api/v1/health", tags=["health"])
def health():
    return {"status": "ok", "version": __version__}


app.include_router(about.router, prefix="/api/v1")  # public: branding + attribution
protected = [Depends(require_api_key)]
for r in (discovery, environments, rules, events, detections, siem, dashboard, demo):
    app.include_router(r.router, prefix="/api/v1", dependencies=protected)
app.include_router(events.ingest_router, prefix="/api/v1", dependencies=protected)

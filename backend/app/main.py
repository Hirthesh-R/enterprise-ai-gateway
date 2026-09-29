"""FastAPI application entry point.

Run locally (SQLite + in-memory rate limiter, no Docker needed)::

    uvicorn app.main:app --app-dir backend --reload --port 8000
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import dashboard, gateway, health
from app.config import get_settings
from app.database import SessionLocal, engine, init_db
from app.errors import register_exception_handlers
from app.middleware.request_logging import RequestLoggingMiddleware
from app.services.container import build_container
from app.services.demo_data import has_transactions, seed_demo_transactions

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
)
logger = logging.getLogger("gateway")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialise DB, seed demo data, connect the rate limiter; clean up on shutdown."""
    container = build_container(settings)
    app.state.container = container

    await init_db()
    async with SessionLocal() as session:
        if settings.seed_demo_keys:
            await container.api_keys.ensure_demo_keys(session)
        if settings.auto_seed_demo_data and settings.demo_transaction_count and not await has_transactions(session):
            await seed_demo_transactions(session, container.api_keys, settings.demo_transaction_count)

    await container.rate_limiter.connect()
    logger.info("%s v%s started [env=%s, db=%s, rate-limiter=%s]", settings.app_name, settings.app_version,
                settings.environment, "sqlite" if settings.is_sqlite else "mysql",
                container.rate_limiter.backend_name)
    try:
        yield
    finally:
        await container.rate_limiter.close()
        await engine.dispose()
        logger.info("Gateway shut down cleanly")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Secure API gateway between users and Large Language Models: PII redaction, prompt-injection defense, "
        "token-based sliding-window rate limiting, audit logging and real-time observability.\n\n"
        "**Demo API keys:** `demo-key-001`, `demo-key-002`, `enterprise-demo-key` (1000 tokens/min), "
        "`legacy-revoked-key` (revoked)."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
    expose_headers=["X-Transaction-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
                    "Retry-After", "X-Request-ID"],
)
register_exception_handlers(app)

app.include_router(health.router)
app.include_router(gateway.router)
app.include_router(dashboard.router)

_frontend = settings.frontend_dir
if _frontend.is_dir():
    app.mount("/static", StaticFiles(directory=_frontend), name="static")

    @app.get("/", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(_frontend / "index.html")
else:  # pragma: no cover
    @app.get("/", include_in_schema=False)
    async def index_missing() -> JSONResponse:
        return JSONResponse({"message": "Frontend not found. API docs at /docs"})

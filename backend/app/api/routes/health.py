"""Health monitoring endpoint."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.database import check_db_connection
from app.schemas.dashboard import HealthResponse
from app.services.container import ServiceContainer, get_container
from app.utils.timeutils import to_iso, utcnow

router = APIRouter(tags=["Health"])
_STARTED = time.monotonic()


@router.get("/health", response_model=HealthResponse, summary="Service health",
            responses={503: {"model": HealthResponse}})
async def health(container: ServiceContainer = Depends(get_container)) -> JSONResponse:
    """Report database and Redis status. Redis being down reports ``fallback`` instead of failing."""
    db_ok = await check_db_connection()
    limiter = container.rate_limiter
    redis_ok = await limiter.ping() if limiter.backend_name == "redis" else False
    body = HealthResponse(
        status="healthy" if db_ok else "degraded",
        database="connected" if db_ok else "unavailable",
        redis="connected" if redis_ok else "fallback",
        rate_limiter_backend=limiter.backend_name,
        environment=container.settings.environment,
        version=container.settings.app_version,
        uptime_seconds=round(time.monotonic() - _STARTED, 1),
        timestamp=to_iso(utcnow()),
    )
    return JSONResponse(body.model_dump(), status_code=200 if db_ok else 503)

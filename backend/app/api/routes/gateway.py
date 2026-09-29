"""Gateway API: the secure proxy endpoint and related helpers."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse

from app.database import SessionLocal
from app.errors import GatewayError
from app.schemas.gateway import (
    SUPPORTED_MODELS,
    ChatRequest,
    ErrorResponse,
    GatewayResponse,
    ModelInfo,
    RateLimitStatus,
)
from app.services.container import ServiceContainer, get_container

router = APIRouter(prefix="/api/v1/gateway", tags=["Gateway"])


def client_ip(request: Request, trust_proxy: bool) -> str | None:
    """Best-effort client IP (honours X-Forwarded-For only when explicitly trusted)."""
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post(
    "/chat",
    response_model=GatewayResponse,
    summary="Send a prompt through the compliance pipeline",
    responses={
        400: {"model": ErrorResponse, "description": "Validation error"},
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        403: {"model": GatewayResponse, "description": "Blocked by injection defense (or revoked key)"},
        429: {"model": ErrorResponse, "description": "Token rate limit exceeded"},
        500: {"model": ErrorResponse, "description": "Internal/upstream error"},
    },
)
async def chat(
    payload: ChatRequest,
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key", include_in_schema=True),
    container: ServiceContainer = Depends(get_container),
) -> JSONResponse:
    """Validate → authenticate → rate-limit → scrub PII → detect injection → forward to the mock LLM.

    Blocked requests return **HTTP 403** with the full security analysis and are never sent to a model.
    """
    outcome = await container.engine.process(
        payload, client_ip(request, container.settings.trust_proxy_headers), header_api_key=x_api_key
    )
    headers = {"X-Transaction-ID": outcome.body["transaction_id"]}
    if outcome.rate_limit is not None:
        headers.update({
            "X-RateLimit-Limit": str(outcome.rate_limit.limit),
            "X-RateLimit-Remaining": str(outcome.rate_limit.remaining),
            "X-RateLimit-Reset": str(round(outcome.rate_limit.reset_in_seconds)),
        })
    return JSONResponse(outcome.body, status_code=outcome.http_status, headers=headers)


@router.get("/models", response_model=list[ModelInfo], summary="List available (mock) LLM models")
async def list_models(container: ServiceContainer = Depends(get_container)) -> list[ModelInfo]:
    return [
        ModelInfo(id=p.model_id, display_name=p.display_name, provider=p.provider_name,
                  latency_range_ms=getattr(p, "latency_range_ms", (0, 0)))
        for p in container.providers.all()
        if p.model_id in SUPPORTED_MODELS
    ]


@router.get("/rate-limit", response_model=RateLimitStatus, summary="Current token budget for an API key",
            responses={401: {"model": ErrorResponse}})
async def rate_limit_status(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    container: ServiceContainer = Depends(get_container),
) -> RateLimitStatus:
    """Inspect the sliding window for the key in the ``X-API-Key`` header without consuming tokens."""
    async with SessionLocal() as session:
        key = await container.api_keys.validate(session, x_api_key)
    if not key.valid:
        raise GatewayError(401 if key.reason != "revoked" else 403,
                           "API key has been revoked" if key.reason == "revoked" else "Invalid API key")
    result = await container.rate_limiter.status(key.key_hash, key.rate_limit)
    return RateLimitStatus(masked_api_key=key.masked_key, rate_limit=result.as_info())

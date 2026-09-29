"""Application exceptions and structured JSON error handlers."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings

logger = logging.getLogger(__name__)


class GatewayError(Exception):
    """An error that maps directly to a structured JSON HTTP response."""

    def __init__(self, status_code: int, error: str, *, detail: Any = None,
                 headers: dict[str, str] | None = None, **extra: Any) -> None:
        super().__init__(error)
        self.status_code = status_code
        self.error = error
        self.detail = detail
        self.headers = headers or {}
        self.extra = {k: v for k, v in extra.items() if v is not None}

    def to_payload(self, request_id: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"error": self.error, "status_code": self.status_code}
        if self.detail is not None:
            payload["detail"] = self.detail
        payload.update(self.extra)
        if request_id:
            payload["request_id"] = request_id
        return payload


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def register_exception_handlers(app: FastAPI) -> None:
    """Attach handlers that turn every failure into a structured JSON body."""

    @app.exception_handler(GatewayError)
    async def _gateway_error(request: Request, exc: GatewayError) -> JSONResponse:
        return JSONResponse(exc.to_payload(_request_id(request)), status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"field": ".".join(str(p) for p in err.get("loc", []) if p != "body") or "body",
             "message": err.get("msg", "Invalid value")}
            for err in exc.errors()
        ]
        return JSONResponse(
            {"error": "Validation error", "status_code": 400, "detail": errors, "request_id": _request_id(request)},
            status_code=400,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        message = exc.detail if isinstance(exc.detail, str) else "HTTP error"
        return JSONResponse(
            {"error": message, "status_code": exc.status_code, "request_id": _request_id(request)},
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        payload: dict[str, Any] = {
            "error": "Internal server error",
            "status_code": 500,
            "request_id": _request_id(request),
        }
        # Never leak internals in production; in dev show only the exception type/message (no traceback).
        if not get_settings().is_production:
            payload["detail"] = f"{type(exc).__name__}: {exc}"
        return JSONResponse(payload, status_code=500)

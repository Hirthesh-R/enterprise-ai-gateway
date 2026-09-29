"""Request logging + security headers (pure ASGI, streaming/SSE safe).

Logs method, path, status and duration for every request and adds
``X-Request-ID`` / ``X-Process-Time-Ms`` headers. Request bodies (which may
contain API keys or PII) and query strings are never logged.
"""

from __future__ import annotations

import logging
import time
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("gateway.access")

_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
]

_QUIET_PATHS = ("/static/", "/favicon")


class RequestLoggingMiddleware:
    """ASGI middleware that times and logs each HTTP request."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex[:16]
        scope.setdefault("state", {})["request_id"] = request_id
        start = time.perf_counter()
        status_holder = {"code": 500}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["code"] = message["status"]
                elapsed = (time.perf_counter() - start) * 1000
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode()))
                headers.append((b"x-process-time-ms", f"{elapsed:.2f}".encode()))
                headers.extend(_SECURITY_HEADERS)
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            path = scope.get("path", "")
            if not path.startswith(_QUIET_PATHS):
                elapsed = (time.perf_counter() - start) * 1000
                level = logging.WARNING if status_holder["code"] >= 500 else logging.INFO
                logger.log(level, "%s %s -> %d (%.1f ms) rid=%s", scope.get("method"), path,
                           status_holder["code"], elapsed, request_id)

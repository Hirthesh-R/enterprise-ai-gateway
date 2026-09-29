"""Token-based sliding-window rate limiter.

Every request "costs" its (approximate) input-token count. A key may spend at
most ``limit`` tokens within any rolling ``window_seconds`` period.

Backends:

* :class:`RedisSlidingWindow` — primary. A sorted set per API key (score =
  timestamp, member = ``<uuid>:<tokens>``) updated atomically by a Lua script,
  so it is safe across multiple gateway replicas.
* :class:`InMemorySlidingWindow` — automatic fallback when Redis is not
  configured or becomes unreachable. Per-process only.

:class:`RateLimiter` orchestrates both and transparently fails over / retries.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Protocol

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RateLimitResult:
    """Outcome of a rate-limit check."""

    allowed: bool
    limit: int
    used: int
    remaining: int
    request_count: int
    window_seconds: int
    reset_in_seconds: float
    retry_after_seconds: int
    backend: str

    def as_info(self) -> dict:
        return {
            "limit": self.limit,
            "used": self.used,
            "remaining": self.remaining,
            "request_count": self.request_count,
            "window_seconds": self.window_seconds,
            "reset_in_seconds": round(self.reset_in_seconds, 2),
            "backend": self.backend,
        }


class SlidingWindowBackend(Protocol):
    name: str

    async def hit(self, key: str, cost: int, limit: int, window: int, now: float) -> RateLimitResult: ...
    async def peek(self, key: str, limit: int, window: int, now: float) -> RateLimitResult: ...
    async def reset(self, key: str | None = None) -> None: ...


def _compute_retry(entries: list[tuple[float, int]], used: int, cost: int, limit: int, window: int, now: float) -> float:
    """Seconds until enough tokens expire from the window to fit ``cost``."""
    if cost > limit:
        return float(window)
    needed = used + cost - limit
    freed = 0
    for ts, tokens in entries:  # entries are sorted oldest → newest
        freed += tokens
        if freed >= needed:
            return max(0.0, ts + window - now)
    return float(window)


def _result(allowed: bool, entries: list[tuple[float, int]], used: int, limit: int, window: int,
            now: float, backend: str, retry: float = 0.0) -> RateLimitResult:
    reset = (entries[0][0] + window - now) if entries else 0.0
    return RateLimitResult(
        allowed=allowed,
        limit=limit,
        used=used,
        remaining=max(0, limit - used),
        request_count=len(entries),
        window_seconds=window,
        reset_in_seconds=max(0.0, reset),
        retry_after_seconds=int(math.ceil(retry)) if not allowed else 0,
        backend=backend,
    )


class InMemorySlidingWindow:
    """Process-local sliding window (fallback backend)."""

    name = "memory"

    def __init__(self) -> None:
        self._events: dict[str, deque[tuple[float, int]]] = {}
        self._lock = asyncio.Lock()

    def _prune(self, key: str, window: int, now: float) -> deque[tuple[float, int]]:
        events = self._events.setdefault(key, deque())
        cutoff = now - window
        while events and events[0][0] <= cutoff:
            events.popleft()
        return events

    async def hit(self, key: str, cost: int, limit: int, window: int, now: float) -> RateLimitResult:
        async with self._lock:
            events = self._prune(key, window, now)
            used = sum(t for _, t in events)
            if used + cost > limit:
                retry = _compute_retry(list(events), used, cost, limit, window, now)
                return _result(False, list(events), used, limit, window, now, self.name, retry)
            events.append((now, cost))
            return _result(True, list(events), used + cost, limit, window, now, self.name)

    async def peek(self, key: str, limit: int, window: int, now: float) -> RateLimitResult:
        async with self._lock:
            events = self._prune(key, window, now)
            return _result(True, list(events), sum(t for _, t in events), limit, window, now, self.name)

    async def reset(self, key: str | None = None) -> None:
        async with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)


_LUA_HIT = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local cost   = tonumber(ARGV[4])
local member = ARGV[5]
local commit = tonumber(ARGV[6])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local entries = redis.call('ZRANGE', key, 0, -1, 'WITHSCORES')
local used = 0
for i = 1, #entries, 2 do
  used = used + tonumber(string.match(entries[i], ':(%d+)$'))
end
local allowed = 0
if commit == 1 and used + cost <= limit then
  redis.call('ZADD', key, now, member .. ':' .. cost)
  redis.call('PEXPIRE', key, window)
  allowed = 1
end
return {allowed, entries}
"""


class RedisSlidingWindow:
    """Redis sorted-set sliding window (primary backend)."""

    name = "redis"

    def __init__(self, client) -> None:  # client: redis.asyncio.Redis
        self._client = client
        self._script = client.register_script(_LUA_HIT)

    @staticmethod
    def _rkey(key: str) -> str:
        return f"ratelimit:tokens:{key}"

    async def _run(self, key: str, cost: int, limit: int, window: int, now: float, commit: bool):
        now_ms, window_ms = int(now * 1000), window * 1000
        allowed, raw = await self._script(
            keys=[self._rkey(key)],
            args=[now_ms, window_ms, limit, cost, uuid.uuid4().hex, 1 if commit else 0],
        )
        entries: list[tuple[float, int]] = []
        for i in range(0, len(raw), 2):
            member = raw[i].decode() if isinstance(raw[i], bytes) else str(raw[i])
            entries.append((float(raw[i + 1]) / 1000.0, int(member.rsplit(":", 1)[1])))
        return bool(allowed), entries

    async def hit(self, key: str, cost: int, limit: int, window: int, now: float) -> RateLimitResult:
        allowed, entries = await self._run(key, cost, limit, window, now, commit=True)
        used = sum(t for _, t in entries)
        if not allowed:
            retry = _compute_retry(entries, used, cost, limit, window, now)
            return _result(False, entries, used, limit, window, now, self.name, retry)
        entries.append((now, cost))
        return _result(True, entries, used + cost, limit, window, now, self.name)

    async def peek(self, key: str, limit: int, window: int, now: float) -> RateLimitResult:
        _, entries = await self._run(key, 0, limit, window, now, commit=False)
        return _result(True, entries, sum(t for _, t in entries), limit, window, now, self.name)

    async def reset(self, key: str | None = None) -> None:
        if key is not None:
            await self._client.delete(self._rkey(key))
            return
        async for rkey in self._client.scan_iter(match="ratelimit:tokens:*"):
            await self._client.delete(rkey)


class RateLimiter:
    """Front-end for the sliding window with automatic Redis → memory failover."""

    def __init__(self, default_limit: int = 100, window_seconds: int = 60,
                 redis_url: str | None = None, retry_interval: int = 30) -> None:
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.redis_url = redis_url
        self.retry_interval = retry_interval
        self._memory = InMemorySlidingWindow()
        self._redis: RedisSlidingWindow | None = None
        self._redis_client = None
        self._last_connect_attempt = 0.0

    # ------------------------------------------------------------------ status
    @property
    def backend_name(self) -> str:
        return "redis" if self._redis is not None else "memory"

    @property
    def redis_status(self) -> str:
        """``connected`` | ``fallback`` (configured but down) | ``disabled``."""
        if self._redis is not None:
            return "connected"
        return "fallback"

    # -------------------------------------------------------------- lifecycle
    async def connect(self) -> bool:
        """Try to connect to Redis; fall back to memory on any failure."""
        self._last_connect_attempt = time.monotonic()
        if not self.redis_url:
            logger.info("REDIS_URL not set — using in-memory rate limiter")
            return False
        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(self.redis_url, socket_connect_timeout=1.5, socket_timeout=1.5)
            await client.ping()
            self.use_redis_client(client)
            logger.info("Rate limiter connected to Redis")
            return True
        except Exception as exc:  # pragma: no cover - depends on infra
            logger.warning("Redis unavailable (%s) — falling back to in-memory rate limiter", exc)
            self._redis = None
            return False

    def use_redis_client(self, client) -> None:
        """Attach an already-connected Redis client (also used by tests)."""
        self._redis_client = client
        self._redis = RedisSlidingWindow(client)

    async def close(self) -> None:
        if self._redis_client is not None:
            try:
                await self._redis_client.aclose()
            except Exception:  # pragma: no cover
                pass
        self._redis = None
        self._redis_client = None

    async def ping(self) -> bool:
        if self._redis_client is None:
            return False
        try:
            return bool(await self._redis_client.ping())
        except Exception:
            return False

    async def _maybe_reconnect(self) -> None:
        if self._redis is None and self.redis_url and \
                time.monotonic() - self._last_connect_attempt > self.retry_interval:
            await self.connect()

    # -------------------------------------------------------------- operations
    async def hit(self, key: str, cost: int, limit: int | None = None) -> RateLimitResult:
        """Consume ``cost`` tokens for ``key`` if the window allows it."""
        limit = limit or self.default_limit
        cost = max(0, int(cost))
        await self._maybe_reconnect()
        now = time.time()
        if self._redis is not None:
            try:
                return await self._redis.hit(key, cost, limit, self.window_seconds, now)
            except Exception as exc:
                logger.warning("Redis rate-limit error (%s) — switching to in-memory fallback", exc)
                self._redis = None
        return await self._memory.hit(key, cost, limit, self.window_seconds, now)

    async def status(self, key: str, limit: int | None = None) -> RateLimitResult:
        """Current window state for ``key`` without consuming tokens."""
        limit = limit or self.default_limit
        now = time.time()
        if self._redis is not None:
            try:
                return await self._redis.peek(key, limit, self.window_seconds, now)
            except Exception as exc:
                logger.warning("Redis rate-limit peek failed (%s) — using fallback", exc)
                self._redis = None
        return await self._memory.peek(key, limit, self.window_seconds, now)

    async def reset(self, key: str | None = None) -> None:
        await self._memory.reset(key)
        if self._redis is not None:
            try:
                await self._redis.reset(key)
            except Exception:  # pragma: no cover
                pass

"""Tests for the token-based sliding-window rate limiter (memory + Redis backends)."""

from __future__ import annotations

import fakeredis.aioredis
import pytest

from app.services import rate_limiter as rl_module
from app.services.rate_limiter import InMemorySlidingWindow, RateLimiter, RedisSlidingWindow

WINDOW = 60


@pytest.fixture()
async def redis_client():
    client = fakeredis.aioredis.FakeRedis()
    yield client
    await client.aclose()


@pytest.fixture(params=["memory", "redis"])
async def backend(request, redis_client):
    """Run the same behavioural tests against both backends."""
    if request.param == "memory":
        return InMemorySlidingWindow()
    return RedisSlidingWindow(redis_client)


# ---------------------------------------------------------------- backends
async def test_allows_until_budget_exhausted(backend) -> None:
    now = 1_000.0
    first = await backend.hit("k", 40, 100, WINDOW, now)
    assert first.allowed and first.used == 40 and first.remaining == 60 and first.request_count == 1
    second = await backend.hit("k", 60, 100, WINDOW, now + 1)
    assert second.allowed and second.used == 100 and second.remaining == 0 and second.request_count == 2
    third = await backend.hit("k", 1, 100, WINDOW, now + 2)
    assert not third.allowed
    assert third.used == 100 and third.remaining == 0
    # The oldest entry (t=1000) must expire before 1 token fits: 1000 + 60 - 1002 = 58s.
    assert third.retry_after_seconds == 58
    assert third.backend == backend.name


async def test_window_slides(backend) -> None:
    await backend.hit("k", 80, 100, WINDOW, 0.0)
    assert not (await backend.hit("k", 30, 100, WINDOW, 30.0)).allowed
    # After the first entry leaves the window the budget is available again.
    later = await backend.hit("k", 30, 100, WINDOW, 60.5)
    assert later.allowed and later.used == 30


async def test_rejected_request_does_not_consume(backend) -> None:
    await backend.hit("k", 90, 100, WINDOW, 0.0)
    assert not (await backend.hit("k", 20, 100, WINDOW, 1.0)).allowed
    assert (await backend.peek("k", 100, WINDOW, 2.0)).used == 90


async def test_keys_are_isolated(backend) -> None:
    await backend.hit("a", 100, 100, WINDOW, 0.0)
    assert (await backend.hit("b", 50, 100, WINDOW, 0.0)).allowed


async def test_cost_larger_than_limit_retries_full_window(backend) -> None:
    result = await backend.hit("k", 150, 100, WINDOW, 0.0)
    assert not result.allowed and result.retry_after_seconds == WINDOW


async def test_peek_and_reset(backend) -> None:
    await backend.hit("k", 25, 100, WINDOW, 10.0)
    await backend.hit("j", 5, 100, WINDOW, 10.0)
    status = await backend.peek("k", 100, WINDOW, 20.0)
    assert status.used == 25 and status.remaining == 75
    assert status.reset_in_seconds == pytest.approx(50.0, abs=0.01)
    await backend.reset("k")
    assert (await backend.peek("k", 100, WINDOW, 20.0)).used == 0
    assert (await backend.peek("j", 100, WINDOW, 20.0)).used == 5
    await backend.reset()
    assert (await backend.peek("j", 100, WINDOW, 20.0)).used == 0


def test_as_info_contains_tracking_fields() -> None:
    import asyncio

    result = asyncio.run(InMemorySlidingWindow().hit("k", 10, 100, WINDOW, 0.0))
    info = result.as_info()
    assert set(info) == {"limit", "used", "remaining", "request_count", "window_seconds",
                         "reset_in_seconds", "backend"}


# ------------------------------------------------------------ RateLimiter
async def test_rate_limiter_memory_default() -> None:
    limiter = RateLimiter(default_limit=100, window_seconds=WINDOW)
    assert await limiter.connect() is False
    assert limiter.backend_name == "memory" and limiter.redis_status == "fallback"
    assert (await limiter.hit("key", 60)).allowed
    blocked = await limiter.hit("key", 60)
    assert not blocked.allowed and blocked.retry_after_seconds > 0
    # Per-key limits override the default.
    assert (await limiter.hit("vip", 500, limit=1000)).allowed
    assert (await limiter.status("key")).used == 60
    await limiter.reset()
    assert (await limiter.status("key")).used == 0
    assert await limiter.ping() is False


async def test_rate_limiter_uses_redis(redis_client) -> None:
    limiter = RateLimiter(default_limit=100, window_seconds=WINDOW)
    limiter.use_redis_client(redis_client)
    assert limiter.backend_name == "redis" and limiter.redis_status == "connected"
    assert await limiter.ping() is True
    result = await limiter.hit("key", 70)
    assert result.allowed and result.backend == "redis"
    assert await redis_client.zcard("ratelimit:tokens:key") == 1
    assert not (await limiter.hit("key", 40)).allowed
    assert (await limiter.status("key")).used == 70
    await limiter.reset("key")
    assert await redis_client.exists("ratelimit:tokens:key") == 0
    await limiter.close()
    assert limiter.backend_name == "memory"


class _BrokenScript:
    async def __call__(self, *args, **kwargs):
        raise ConnectionError("redis went away")


class _BrokenRedis:
    def register_script(self, _script):
        return _BrokenScript()

    async def ping(self):
        raise ConnectionError("redis went away")

    async def aclose(self):
        return None


async def test_failover_to_memory_on_redis_error() -> None:
    limiter = RateLimiter(default_limit=100, window_seconds=WINDOW)
    limiter.use_redis_client(_BrokenRedis())
    assert limiter.backend_name == "redis"
    assert await limiter.ping() is False
    result = await limiter.hit("key", 10)
    assert result.allowed and result.backend == "memory"
    assert limiter.backend_name == "memory" and limiter.redis_status == "fallback"


async def test_status_failover_to_memory() -> None:
    limiter = RateLimiter(default_limit=100, window_seconds=WINDOW)
    limiter.use_redis_client(_BrokenRedis())
    status = await limiter.status("key")
    assert status.backend == "memory"


async def test_unreachable_redis_url_falls_back() -> None:
    limiter = RateLimiter(redis_url="redis://127.0.0.1:1/0", retry_interval=0)
    assert await limiter.connect() is False
    assert limiter.backend_name == "memory"
    # Reconnect attempts happen transparently and never raise.
    assert (await limiter.hit("key", 5)).allowed


async def test_sliding_window_with_patched_clock(monkeypatch) -> None:
    clock = {"now": 5_000.0}
    monkeypatch.setattr(rl_module.time, "time", lambda: clock["now"])
    limiter = RateLimiter(default_limit=100, window_seconds=WINDOW)
    await limiter.hit("key", 100)
    clock["now"] += 30
    assert not (await limiter.hit("key", 1)).allowed
    clock["now"] += 31
    assert (await limiter.hit("key", 1)).allowed

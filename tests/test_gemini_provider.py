"""Tests for the live Gemini provider, using a fake client (no network, no API key)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.services.gemini_provider import AllModelsFailedError, GeminiProvider


class FakeModels:
    """Imitates ``client.aio.models``: each model name maps to a reply or an exception."""

    def __init__(self, behaviour: dict) -> None:
        self.behaviour = behaviour
        self.calls: list[tuple[str, str]] = []

    async def generate_content(self, model: str, contents: str):
        self.calls.append((model, contents))
        outcome = self.behaviour[model]
        if outcome == "hang":
            await asyncio.sleep(10)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def make_provider(behaviour: dict, models: list[str], timeout: float = 5.0):
    fake = FakeModels(behaviour)
    client = SimpleNamespace(aio=SimpleNamespace(models=fake))
    provider = GeminiProvider(api_key=None, models=models, timeout_seconds=timeout, client=client)
    return provider, fake


def reply(text: str, output_tokens: int | None = None):
    usage = SimpleNamespace(candidates_token_count=output_tokens) if output_tokens is not None else None
    return SimpleNamespace(text=text, usage_metadata=usage)


async def test_returns_text_and_provider_token_count():
    provider, fake = make_provider({"m1": reply("Hello Hirthesh", output_tokens=4)}, ["m1"])
    result = await provider.generate("Say hello")
    assert result.text == "Hello Hirthesh"
    assert result.model == "m1"
    assert result.output_tokens == 4
    assert result.provider == "Google Gemini (live)"
    assert fake.calls == [("m1", "Say hello")]
    assert provider.invocation_count == 1
    assert provider.fallback_count == 0


async def test_falls_back_when_first_model_is_overloaded():
    provider, fake = make_provider(
        {"busy": RuntimeError("503 UNAVAILABLE"), "ok": reply("from backup")}, ["busy", "ok"])
    result = await provider.generate("hi")
    assert result.text == "from backup"
    assert result.model == "ok"
    assert [m for m, _ in fake.calls] == ["busy", "ok"]
    assert provider.fallback_count == 1


async def test_falls_back_after_timeout():
    provider, _ = make_provider({"slow": "hang", "fast": reply("quick")}, ["slow", "fast"], timeout=0.05)
    result = await provider.generate("hi")
    assert result.model == "fast"


async def test_raises_when_every_model_fails():
    provider, _ = make_provider(
        {"a": RuntimeError("503 UNAVAILABLE"), "b": RuntimeError("404 NOT_FOUND")}, ["a", "b"])
    with pytest.raises(AllModelsFailedError) as info:
        await provider.generate("hi")
    assert [m for m, _ in info.value.failures] == ["a", "b"]


async def test_empty_text_and_missing_usage_are_handled():
    provider, _ = make_provider({"m1": reply("")}, ["m1"])
    result = await provider.generate("hi")
    assert result.text == ""
    assert result.output_tokens == 0


def test_requires_at_least_one_model():
    with pytest.raises(ValueError):
        GeminiProvider(api_key=None, models=[], client=SimpleNamespace())

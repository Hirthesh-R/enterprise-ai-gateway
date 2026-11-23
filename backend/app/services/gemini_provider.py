"""Real Google Gemini provider with timeouts and model fallback.

The gateway's security pipeline is unchanged: this provider only receives the
already-sanitised prompt, exactly like the mock providers.

Reliability: Gemini models are sometimes overloaded (HTTP 503) or retired
(HTTP 404). The provider therefore tries an ordered list of models
(``GEMINI_MODELS``) and returns the first successful answer. Each attempt has
its own timeout, so one slow model cannot hang the request.
"""

from __future__ import annotations

import asyncio
import logging
import time

from app.services.llm_provider import LLMProvider, LLMResponse
from app.utils.token_counter import count_tokens

logger = logging.getLogger(__name__)


class AllModelsFailedError(RuntimeError):
    """Raised when every configured Gemini model failed for one request."""

    def __init__(self, failures: list[tuple[str, str]]) -> None:
        self.failures = failures
        summary = "; ".join(f"{model}: {reason}" for model, reason in failures)
        super().__init__(f"All Gemini models failed ({summary})")


class GeminiProvider(LLMProvider):
    """Calls Google Gemini through the official ``google-genai`` SDK."""

    def __init__(self, api_key: str | None, models: list[str], *, model_id: str = "gemini-pro",
                 display_name: str = "Gemini Pro", timeout_seconds: float = 20.0, client=None) -> None:
        if not models:
            raise ValueError("GeminiProvider needs at least one model name")
        self.model_id = model_id
        self.display_name = display_name
        self.provider_name = "Google Gemini (live)"
        self.models = list(models)
        self.timeout_seconds = timeout_seconds
        self.invocation_count = 0
        self.fallback_count = 0
        if client is None:
            # Imported lazily so tests and CI never need the SDK or an API key.
            from google import genai

            client = genai.Client(api_key=api_key)
        self._client = client

    @staticmethod
    def _output_tokens(response, text: str) -> int:
        usage = getattr(response, "usage_metadata", None)
        tokens = getattr(usage, "candidates_token_count", None) if usage is not None else None
        return int(tokens) if tokens else count_tokens(text)

    async def generate(self, prompt: str) -> LLMResponse:
        start = time.perf_counter()
        failures: list[tuple[str, str]] = []

        for attempt, model in enumerate(self.models):
            try:
                response = await asyncio.wait_for(
                    self._client.aio.models.generate_content(model=model, contents=prompt),
                    timeout=self.timeout_seconds,
                )
            except asyncio.TimeoutError:
                failures.append((model, f"timeout after {self.timeout_seconds:g}s"))
                logger.warning("Gemini model %s timed out; trying next model", model)
                continue
            except Exception as exc:  # SDK raises APIError subclasses (404, 429, 503, ...)
                failures.append((model, str(exc)[:160]))
                logger.warning("Gemini model %s failed (%s); trying next model", model, str(exc)[:160])
                continue

            text = getattr(response, "text", None) or ""
            if attempt > 0:
                self.fallback_count += 1
            self.invocation_count += 1
            latency = (time.perf_counter() - start) * 1000
            return LLMResponse(text=text, model=model, provider=self.provider_name,
                               latency_ms=round(latency, 2), output_tokens=self._output_tokens(response, text))

        raise AllModelsFailedError(failures)

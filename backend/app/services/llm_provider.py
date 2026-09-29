"""LLM provider abstraction with deterministic mock implementations.

:class:`LLMProvider` is the interface every provider implements. The shipped
mock providers simulate realistic latency and return deterministic answers
derived from the prompt content, so the gateway is fully demoable without paid
APIs. A real provider (OpenAI, Vertex AI, Anthropic, …) only needs to subclass
:class:`LLMProvider` and be registered in :class:`ProviderRegistry`.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.utils.token_counter import count_tokens


@dataclass(slots=True)
class LLMResponse:
    """Normalised provider response."""

    text: str
    model: str
    provider: str
    latency_ms: float
    output_tokens: int


class LLMProvider(ABC):
    """Interface for all LLM providers."""

    model_id: str
    display_name: str
    provider_name: str

    @abstractmethod
    async def generate(self, prompt: str) -> LLMResponse:
        """Generate a completion for an already-sanitised prompt."""


# Topic keyword → answer templates. ``{topic}`` is replaced by the prompt subject.
_TOPICS: list[tuple[tuple[str, ...], list[str]]] = [
    (("security", "threat", "vulnerab", "attack", "breach", "zero trust"), [
        "From a security standpoint, {topic} should be addressed with defence-in-depth: enforce least-privilege access, "
        "monitor continuously, and automate incident response playbooks.",
        "A robust approach to {topic} combines threat modelling, strong identity controls and centralised audit logging "
        "so anomalies can be detected and contained quickly.",
    ]),
    (("complian", "gdpr", "hipaa", "soc 2", "soc2", "pci", "regulat", "audit"), [
        "For {topic}, map each requirement to a concrete control, keep evidence in an immutable audit trail and review "
        "data-retention policies quarterly.",
        "Compliance for {topic} is easiest when data minimisation, encryption at rest and in transit, and documented "
        "access reviews are built into the delivery pipeline.",
    ]),
    (("code", "python", "function", "api", "sql", "javascript", "bug", "debug"), [
        "Here is a suggested approach for {topic}: break the problem into small, testable functions, validate inputs "
        "early, and add unit tests for the edge cases before optimising.",
        "To implement {topic}, start with a clear interface, handle errors explicitly, and document assumptions. "
        "Add integration tests around external dependencies.",
    ]),
    (("summar", "report", "quarter", "q1", "q2", "q3", "q4", "revenue", "sales"), [
        "Summary of {topic}: key metrics trended positively, with the main risks concentrated in a few areas that "
        "warrant follow-up actions and owners.",
        "Executive overview of {topic}: performance is on track, costs are stable, and three initiatives are recommended "
        "for the next planning cycle.",
    ]),
    (("customer", "email", "support", "ticket", "refund", "account", "order"), [
        "Regarding {topic}: acknowledge the customer's concern, confirm the relevant account details through a verified "
        "channel, and outline the next steps with a clear timeline.",
        "A good response for {topic} is empathetic, concise and action-oriented, and avoids repeating sensitive "
        "personal information back to the customer.",
    ]),
    (("data", "machine learning", "ml", "model", "ai", "llm", "analytics"), [
        "For {topic}, ensure data quality first, track lineage, and evaluate models against a held-out set with "
        "business-relevant metrics before deployment.",
        "{topic} benefits from a governed data platform, reproducible pipelines and ongoing monitoring for drift and bias.",
    ]),
]

_GENERIC = [
    "Here is a concise answer about {topic}: consider the goals, constraints and stakeholders, then iterate on a small "
    "pilot before scaling the solution.",
    "Regarding {topic}: the most effective path is to define success criteria up front, gather the necessary context, "
    "and validate the outcome with measurable checkpoints.",
    "On {topic}: a practical plan is to prioritise the highest-impact items, document decisions, and review progress "
    "regularly with the team.",
]

_STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "of", "for", "in", "on", "is", "are", "me", "my", "please", "can", "you",
    "how", "what", "why", "do", "i", "we", "our", "with", "about", "give", "tell", "write", "explain", "at", "it",
    "this", "that", "be", "should", "could", "would", "from", "by", "as", "your", "some", "list",
}


def _extract_topic(prompt: str) -> str:
    """Pick a short subject phrase from the prompt (placeholders excluded)."""
    clean = re.sub(r"\[REDACTED_[A-Z_]+\]", " ", prompt)
    words = [w for w in re.findall(r"[A-Za-z][A-Za-z0-9'-]*", clean) if w.lower() not in _STOPWORDS]
    return " ".join(words[:4]).lower() or "your request"


class MockLLMProvider(LLMProvider):
    """Deterministic mock provider with simulated latency."""

    def __init__(self, model_id: str, display_name: str, provider_name: str,
                 latency_range_ms: tuple[int, int], style: str, latency_scale: float = 1.0) -> None:
        self.model_id = model_id
        self.display_name = display_name
        self.provider_name = provider_name
        self.latency_range_ms = latency_range_ms
        self.style = style
        self.latency_scale = latency_scale
        #: Number of times this provider was invoked (used to prove blocked prompts never arrive).
        self.invocation_count = 0

    def render(self, prompt: str) -> str:
        """Deterministically build the response text for ``prompt`` (no latency)."""
        digest = int(hashlib.sha256(f"{self.model_id}:{prompt}".encode()).hexdigest(), 16)
        lowered = prompt.lower()
        templates = _GENERIC
        for keywords, options in _TOPICS:
            if any(k in lowered for k in keywords):
                templates = options
                break
        body = templates[digest % len(templates)].format(topic=_extract_topic(prompt))
        redaction_note = ""
        if "[REDACTED_" in prompt:
            redaction_note = " (Note: sensitive personal data in your request was redacted by the gateway before processing.)"
        return f"{self.style} {body}{redaction_note}"

    async def generate(self, prompt: str) -> LLMResponse:
        self.invocation_count += 1
        start = time.perf_counter()
        low, high = self.latency_range_ms
        delay_ms = random.uniform(low, high) * self.latency_scale
        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000.0)
        text = self.render(prompt)
        latency = (time.perf_counter() - start) * 1000
        return LLMResponse(text=text, model=self.model_id, provider=self.provider_name,
                           latency_ms=round(latency, 2), output_tokens=count_tokens(text))


class ProviderRegistry:
    """Resolves a model id to its provider instance."""

    def __init__(self) -> None:
        self._providers: dict[str, LLMProvider] = {}

    def register(self, provider: LLMProvider) -> None:
        self._providers[provider.model_id] = provider

    def get(self, model_id: str) -> LLMProvider:
        try:
            return self._providers[model_id]
        except KeyError as exc:
            raise ValueError(f"Unsupported model: {model_id}") from exc

    def all(self) -> list[LLMProvider]:
        return list(self._providers.values())

    @property
    def total_invocations(self) -> int:
        return sum(getattr(p, "invocation_count", 0) for p in self._providers.values())


MOCK_MODEL_SPECS: dict[str, dict] = {
    "gpt-4": {"display_name": "GPT-4", "provider_name": "OpenAI (mock)", "latency_range_ms": (100, 300),
              "style": "[GPT-4]"},
    "gemini-pro": {"display_name": "Gemini Pro", "provider_name": "Google (mock)", "latency_range_ms": (120, 350),
                   "style": "[Gemini Pro]"},
    "claude": {"display_name": "Claude", "provider_name": "Anthropic (mock)", "latency_range_ms": (110, 320),
               "style": "[Claude]"},
    "llama": {"display_name": "Llama", "provider_name": "Meta (mock)", "latency_range_ms": (80, 250),
              "style": "[Llama]"},
}


def build_mock_registry(latency_scale: float = 1.0) -> ProviderRegistry:
    """Create a registry populated with all mock providers."""
    registry = ProviderRegistry()
    for model_id, spec in MOCK_MODEL_SPECS.items():
        registry.register(MockLLMProvider(model_id=model_id, latency_scale=latency_scale, **spec))
    return registry

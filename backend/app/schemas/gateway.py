"""Request/response schemas for the gateway API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: Canonical model identifiers accepted by the gateway.
SUPPORTED_MODELS: dict[str, str] = {
    "gpt-4": "GPT-4",
    "gemini-pro": "Gemini Pro",
    "claude": "Claude",
    "llama": "Llama",
}

_MODEL_ALIASES: dict[str, str] = {
    "gpt4": "gpt-4",
    "gpt-4": "gpt-4",
    "gemini": "gemini-pro",
    "gemini-pro": "gemini-pro",
    "geminipro": "gemini-pro",
    "claude": "claude",
    "llama": "llama",
}

ModelId = Literal["gpt-4", "gemini-pro", "claude", "llama"]
TransactionStatus = Literal["allowed", "blocked", "rate_limited", "unauthorized", "forbidden", "error"]


class ChatRequest(BaseModel):
    """Inbound gateway request."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "prompt": "Summarise our Q3 security posture. Contact me at jane@example.com",
                "api_key": "demo-key-001",
                "target_model": "gpt-4",
                "enable_pii_scrubbing": True,
                "enable_injection_defense": True,
            }
        },
    )

    prompt: str = Field(..., min_length=1, max_length=8000, description="User prompt")
    api_key: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        description="Gateway API key (may alternatively be sent via the X-API-Key header)",
    )
    target_model: ModelId = Field(default="gpt-4", description="gpt-4 | gemini-pro | claude | llama")
    enable_pii_scrubbing: bool = True
    enable_injection_defense: bool = True

    @field_validator("target_model", mode="before")
    @classmethod
    def _normalise_model(cls, value: Any) -> Any:
        """Accept friendly aliases such as ``GPT-4`` or ``Gemini Pro``."""
        if isinstance(value, str):
            key = value.strip().lower().replace(" ", "-").replace("_", "-")
            return _MODEL_ALIASES.get(key, key)
        return value

    @field_validator("prompt")
    @classmethod
    def _reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("prompt must not be blank")
        return value


class TokenUsageSchema(BaseModel):
    input_tokens: int
    output_tokens: int
    total_tokens: int


class RateLimitInfo(BaseModel):
    """Sliding-window quota state for the calling API key."""

    limit: int
    used: int
    remaining: int
    request_count: int
    window_seconds: int
    reset_in_seconds: float
    backend: str


class PipelineStage(BaseModel):
    """One step of the compliance pipeline trace (shown in the playground)."""

    stage: str
    status: Literal["passed", "failed", "skipped", "flagged"]
    duration_ms: float
    detail: str = ""


class PIIFinding(BaseModel):
    type: str
    count: int


class GatewayResponse(BaseModel):
    """Result of a gateway request (allowed or blocked)."""

    transaction_id: str
    timestamp: str
    status: TransactionStatus
    security_decision: Literal["ALLOWED", "BLOCKED"]
    blocked: bool
    target_model: str
    model_display_name: str
    masked_api_key: str

    original_prompt_status: str
    sanitized_prompt: str
    response: str | None

    pii_detected: bool
    pii_redacted: bool
    redaction_count: int
    detected_types: list[str]
    pii_findings: list[PIIFinding]

    injection_detected: bool
    threat_type: str | None = None
    risk_level: str | None = None
    matched_rules: list[str] = []

    input_tokens: int
    output_tokens: int
    total_tokens: int
    token_usage: TokenUsageSchema

    processing_time_ms: float
    llm_latency_ms: float
    rate_limit: RateLimitInfo | None = None
    pipeline: list[PipelineStage]
    error: str | None = None


class ErrorResponse(BaseModel):
    """Structured error payload returned for every non-2xx response."""

    error: str
    status_code: int
    detail: Any | None = None
    transaction_id: str | None = None
    retry_after_seconds: int | None = None
    request_id: str | None = None


class RateLimitStatus(BaseModel):
    masked_api_key: str
    rate_limit: RateLimitInfo


class ModelInfo(BaseModel):
    id: str
    display_name: str
    provider: str
    latency_range_ms: tuple[int, int]

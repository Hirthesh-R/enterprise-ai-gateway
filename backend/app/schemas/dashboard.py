"""Schemas for the observability dashboard API."""

from __future__ import annotations

from pydantic import BaseModel


class KPIResponse(BaseModel):
    total_requests: int
    allowed_requests: int
    blocked_attacks: int
    pii_redactions: int
    pii_requests: int
    avg_response_time_ms: float
    p95_response_time_ms: float
    total_tokens: int
    rate_limit_violations: int
    unauthorized_requests: int
    block_rate_pct: float
    requests_last_hour: int
    generated_at: str


class TimeSeries(BaseModel):
    labels: list[str]
    datasets: dict[str, list[float | None]]


class Distribution(BaseModel):
    labels: list[str]
    values: list[int]


class ModelUsage(BaseModel):
    labels: list[str]
    allowed: list[int]
    blocked: list[int]
    avg_latency_ms: list[float]


class ChartsResponse(BaseModel):
    window_minutes: int
    bucket_minutes: int
    requests_per_minute: TimeSeries
    response_latency: TimeSeries
    threat_distribution: Distribution
    model_usage: ModelUsage
    pii_type_distribution: Distribution
    generated_at: str


class AuditItem(BaseModel):
    transaction_id: str
    timestamp: str
    masked_api_key: str
    target_model: str
    status: str
    http_status: int
    processing_time_ms: float
    input_tokens: int
    output_tokens: int
    total_tokens: int
    pii_detected: bool
    pii_redacted: bool
    redaction_count: int
    pii_types: list[str]
    injection_detected: bool
    threat_type: str | None
    risk_level: str | None
    masked_ip: str
    prompt_preview: str


class AuditPage(BaseModel):
    items: list[AuditItem]
    total: int
    page: int
    page_size: int
    pages: int


class ThreatEventItem(BaseModel):
    transaction_id: str
    timestamp: str
    threat_type: str
    risk_level: str
    action: str
    masked_ip: str
    masked_api_key: str
    matched_rules: list[str]


class ApiKeyInfo(BaseModel):
    key_name: str
    masked_key: str
    status: str
    rate_limit: int
    created_at: str
    last_used_at: str | None


class HealthResponse(BaseModel):
    status: str
    database: str
    redis: str
    rate_limiter_backend: str
    environment: str
    version: str
    uptime_seconds: float
    timestamp: str

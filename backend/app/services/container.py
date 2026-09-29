"""Service wiring (a tiny dependency-injection container)."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from app.config import Settings
from app.database import SessionLocal
from app.services.api_key_service import ApiKeyService
from app.services.compliance_engine import ComplianceEngine
from app.services.injection_detector import InjectionDetector, build_detector
from app.services.llm_provider import ProviderRegistry, build_mock_registry
from app.services.pii_scrubber import PIIScrubber
from app.services.rate_limiter import RateLimiter
from app.services.telemetry_service import EventBroadcaster, TelemetryService


@dataclass(slots=True)
class ServiceContainer:
    settings: Settings
    api_keys: ApiKeyService
    rate_limiter: RateLimiter
    pii_scrubber: PIIScrubber
    injection_detector: InjectionDetector
    providers: ProviderRegistry
    broadcaster: EventBroadcaster
    telemetry: TelemetryService
    engine: ComplianceEngine


def build_container(settings: Settings) -> ServiceContainer:
    """Instantiate every service from configuration."""
    api_keys = ApiKeyService(settings.api_secret)
    limiter = RateLimiter(settings.rate_limit_tokens, settings.rate_limit_window_seconds,
                          settings.redis_url, settings.redis_retry_interval_seconds)
    scrubber = PIIScrubber()
    detector = build_detector(settings.injection_block_threshold, settings.injection_rules_file)
    providers = build_mock_registry(settings.mock_latency_scale)
    broadcaster = EventBroadcaster()
    telemetry = TelemetryService(SessionLocal, broadcaster)
    engine = ComplianceEngine(settings, SessionLocal, api_keys, limiter, scrubber, detector, providers, telemetry)
    return ServiceContainer(settings, api_keys, limiter, scrubber, detector, providers, broadcaster, telemetry, engine)


def get_container(request: Request) -> ServiceContainer:
    """FastAPI dependency returning the application's service container."""
    return request.app.state.container

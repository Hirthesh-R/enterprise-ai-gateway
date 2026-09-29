"""Compliance engine — orchestrates the full gateway security pipeline.

    REQUEST → Validation → API key → Rate limit → PII detection → PII redaction
            → Injection detection → ALLOW/BLOCK → Mock LLM → Telemetry → DB → RESPONSE

Invariants enforced here:

* Blocked requests are **never** forwarded to an LLM provider.
* Raw API keys and raw PII never reach the database or logs: keys are stored
  as HMAC hashes + masked form, and the stored prompt preview is always fully
  redacted — even if the caller disabled scrubbing for the LLM call.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.errors import GatewayError
from app.models.transaction import Transaction
from app.schemas.gateway import SUPPORTED_MODELS, ChatRequest
from app.services.api_key_service import ApiKeyService
from app.services.injection_detector import InjectionDetector
from app.services.llm_provider import ProviderRegistry
from app.services.pii_scrubber import PIIScrubber
from app.services.rate_limiter import RateLimiter, RateLimitResult
from app.services.telemetry_service import TelemetryService, ThreatRecord, truncate_preview
from app.utils.masking import mask_ip
from app.utils.timeutils import to_iso, utcnow
from app.utils.token_counter import TokenUsage, count_tokens

logger = logging.getLogger(__name__)


def new_transaction_id() -> str:
    """Unique, URL-safe transaction id such as ``txn_4f9c0e7b2a1d4c3e9b8a7f60``."""
    return f"txn_{uuid.uuid4().hex[:24]}"


@dataclass(slots=True)
class _Trace:
    """Collects per-stage timings for the pipeline trace."""

    stages: list[dict] = field(default_factory=list)
    _mark: float = field(default_factory=time.perf_counter)

    def add(self, stage: str, status: str, detail: str = "") -> None:
        now = time.perf_counter()
        self.stages.append({"stage": stage, "status": status,
                            "duration_ms": round((now - self._mark) * 1000, 3), "detail": detail})
        self._mark = now


@dataclass(slots=True)
class GatewayOutcome:
    """Final result handed back to the HTTP layer."""

    http_status: int
    body: dict
    rate_limit: RateLimitResult | None = None


class ComplianceEngine:
    """Runs every gateway request through the security pipeline."""

    def __init__(self, settings: Settings, session_factory: async_sessionmaker[AsyncSession],
                 api_keys: ApiKeyService, rate_limiter: RateLimiter, pii_scrubber: PIIScrubber,
                 injection_detector: InjectionDetector, providers: ProviderRegistry,
                 telemetry: TelemetryService) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self.api_keys = api_keys
        self.rate_limiter = rate_limiter
        self.pii = pii_scrubber
        self.detector = injection_detector
        self.providers = providers
        self.telemetry = telemetry

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _elapsed_ms(start: float) -> float:
        return round((time.perf_counter() - start) * 1000, 2)

    def _base_txn(self, txn_id: str, *, key_hash: str, masked_key: str, model: str,
                  client_ip: str | None, preview: str) -> Transaction:
        return Transaction(transaction_id=txn_id, timestamp=utcnow(), api_key_hash=key_hash,
                           masked_api_key=masked_key, target_model=model, masked_ip=mask_ip(client_ip),
                           prompt_preview=truncate_preview(preview))

    # --------------------------------------------------------------- pipeline
    async def process(self, req: ChatRequest, client_ip: str | None,
                      header_api_key: str | None = None) -> GatewayOutcome:
        start = time.perf_counter()
        trace = _Trace()
        txn_id = new_transaction_id()
        model = req.target_model
        prompt = req.prompt

        # Always-redacted copy used for storage/logging regardless of user toggles.
        storage_scan = self.pii.scrub(prompt)
        stored_preview = storage_scan.redacted_text

        # 1. Validation -------------------------------------------------------
        if len(prompt) > self.settings.max_prompt_chars:
            raise GatewayError(400, "Validation error",
                               detail=[{"field": "prompt",
                                        "message": f"prompt exceeds {self.settings.max_prompt_chars} characters"}])
        if model not in SUPPORTED_MODELS:  # pragma: no cover - guarded by schema
            raise GatewayError(400, "Validation error", detail=[{"field": "target_model", "message": "unsupported"}])
        trace.add("validation", "passed", f"{len(prompt)} chars, model={model}")

        # 2. API key validation ----------------------------------------------
        raw_key = req.api_key or header_api_key
        async with self.session_factory() as session:
            key = await self.api_keys.validate(session, raw_key)
            if key.valid:
                await self.api_keys.touch(session, key.key_hash)
                await session.commit()

        input_tokens = count_tokens(prompt)
        if not key.valid:
            revoked = key.reason == "revoked"
            status_code = 403 if revoked else 401
            txn = self._base_txn(txn_id, key_hash=key.key_hash, masked_key=key.masked_key, model=model,
                                 client_ip=client_ip, preview=stored_preview)
            txn.status = "forbidden" if revoked else "unauthorized"
            txn.http_status = status_code
            txn.input_tokens = txn.total_tokens = input_tokens
            txn.pii_detected = storage_scan.has_pii
            txn.pii_types = ",".join(storage_scan.detected_types)
            txn.processing_time_ms = self._elapsed_ms(start)
            threat = ThreatRecord("REVOKED_KEY_USAGE" if revoked else "UNAUTHORIZED_ACCESS",
                                  "MEDIUM", "REJECTED", [key.reason or "invalid"])
            await self.telemetry.record(txn, [threat])
            message = {"missing": "API key required", "invalid": "Invalid API key",
                       "revoked": "API key has been revoked"}[key.reason or "invalid"]
            raise GatewayError(status_code, message, transaction_id=txn_id,
                               headers={"WWW-Authenticate": "ApiKey"} if not revoked else None)
        trace.add("authentication", "passed", f"key {key.masked_key} ({key.key_name})")

        # 3. Rate limiting ------------------------------------------------------
        rl = await self.rate_limiter.hit(key.key_hash, input_tokens, key.rate_limit)
        if not rl.allowed:
            txn = self._base_txn(txn_id, key_hash=key.key_hash, masked_key=key.masked_key, model=model,
                                 client_ip=client_ip, preview=stored_preview)
            txn.status, txn.http_status = "rate_limited", 429
            txn.input_tokens = txn.total_tokens = input_tokens
            txn.pii_detected = storage_scan.has_pii
            txn.pii_types = ",".join(storage_scan.detected_types)
            txn.processing_time_ms = self._elapsed_ms(start)
            await self.telemetry.record(txn, [ThreatRecord("RATE_LIMIT_EXCEEDED", "LOW", "THROTTLED",
                                                           [f"{rl.used}+{input_tokens}>{rl.limit}"])])
            raise GatewayError(
                429, "Rate limit exceeded",
                detail=f"Token budget of {rl.limit} tokens per {rl.window_seconds}s exhausted "
                       f"({rl.used} used, request needs {input_tokens}).",
                retry_after_seconds=max(1, rl.retry_after_seconds),
                transaction_id=txn_id,
                rate_limit=rl.as_info(),
                headers={"Retry-After": str(max(1, rl.retry_after_seconds)),
                         "X-RateLimit-Limit": str(rl.limit), "X-RateLimit-Remaining": str(rl.remaining)},
            )
        trace.add("rate_limit", "passed", f"{rl.used}/{rl.limit} tokens used in window ({rl.backend})")

        # 4 + 5. PII detection & redaction ------------------------------------
        pii_result = storage_scan
        trace.add("pii_detection", "flagged" if pii_result.has_pii else "passed",
                  ", ".join(f"{t}×{c}" for t, c in pii_result.counts.items()) or "no PII found")
        if req.enable_pii_scrubbing:
            sanitized = pii_result.redacted_text
            pii_redacted = pii_result.has_pii
            trace.add("pii_redaction", "passed",
                      f"{pii_result.redaction_count} value(s) redacted" if pii_redacted else "nothing to redact")
        else:
            sanitized = prompt
            pii_redacted = False
            trace.add("pii_redaction", "skipped", "PII scrubbing disabled by caller")

        # 6. Prompt-injection detection --------------------------------------
        detection = self.detector.detect(prompt)
        blocked = req.enable_injection_defense and detection.blocked
        if not detection.detected:
            trace.add("injection_detection", "passed", "no injection patterns matched")
        elif blocked:
            trace.add("injection_detection", "failed",
                      f"{detection.threat_type} ({detection.risk_level}) via {', '.join(detection.matched_rules)}")
        elif not req.enable_injection_defense:
            trace.add("injection_detection", "flagged",
                      f"defense disabled — monitor only: {detection.threat_type} ({detection.risk_level})")
        else:
            trace.add("injection_detection", "flagged",
                      f"{detection.threat_type} ({detection.risk_level}) below block threshold")

        txn = self._base_txn(txn_id, key_hash=key.key_hash, masked_key=key.masked_key, model=model,
                             client_ip=client_ip, preview=stored_preview)
        txn.pii_detected = pii_result.has_pii
        txn.pii_redacted = pii_redacted
        txn.redaction_count = pii_result.redaction_count if pii_redacted else 0
        txn.pii_types = ",".join(pii_result.detected_types)
        txn.injection_detected = detection.detected
        txn.threat_type = detection.threat_type
        txn.risk_level = detection.risk_level

        threats: list[ThreatRecord] = []
        response_text: str | None = None
        llm_latency = 0.0
        output_tokens = 0

        # 7. Policy decision -------------------------------------------------
        if blocked:
            trace.add("policy_decision", "failed", "BLOCK — request never forwarded to the LLM")
            threats.append(ThreatRecord(detection.threat_type, detection.risk_level, "BLOCKED",
                                        detection.matched_rules))
            txn.status, txn.http_status = "blocked", 403
            trace.add("llm_forwarding", "skipped", "blocked by policy")
        else:
            if detection.detected:
                threats.append(ThreatRecord(detection.threat_type, detection.risk_level, "MONITORED",
                                            detection.matched_rules))
            trace.add("policy_decision", "passed", "ALLOW")

            # 8. Forward to (mock) LLM ----------------------------------------
            provider = self.providers.get(model)
            try:
                llm = await provider.generate(sanitized)
            except Exception as exc:
                logger.exception("LLM provider %s failed for %s", model, txn_id)
                txn.status, txn.http_status = "error", 500
                txn.input_tokens = txn.total_tokens = input_tokens
                txn.processing_time_ms = self._elapsed_ms(start)
                await self.telemetry.record(txn, threats)
                raise GatewayError(500, "Upstream model error", transaction_id=txn_id) from exc
            response_text, llm_latency, output_tokens = llm.text, llm.latency_ms, llm.output_tokens
            txn.status, txn.http_status = "allowed", 200
            trace.add("llm_forwarding", "passed", f"{provider.display_name} responded in {llm_latency:.0f} ms")

        usage = TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens)
        txn.input_tokens, txn.output_tokens, txn.total_tokens = usage.input_tokens, usage.output_tokens, usage.total_tokens
        txn.llm_latency_ms = llm_latency
        txn.processing_time_ms = self._elapsed_ms(start)

        # 9 + 10. Telemetry & database ---------------------------------------
        persisted = await self.telemetry.record(txn, threats)
        trace.add("telemetry", "passed" if persisted else "failed",
                  "audit record stored" if persisted else "audit persistence failed")

        if pii_result.has_pii and req.enable_pii_scrubbing:
            prompt_status = f"Contained PII — {pii_result.redaction_count} value(s) redacted before forwarding"
        elif pii_result.has_pii:
            prompt_status = "Contained PII — scrubbing disabled, forwarded unredacted (audit copy redacted)"
        else:
            prompt_status = "Clean — no PII detected"
        if blocked:
            prompt_status += "; blocked by injection defense"

        body = {
            "transaction_id": txn_id,
            "timestamp": to_iso(txn.timestamp),
            "status": txn.status,
            "security_decision": "BLOCKED" if blocked else "ALLOWED",
            "blocked": blocked,
            "target_model": model,
            "model_display_name": SUPPORTED_MODELS[model],
            "masked_api_key": key.masked_key,
            "original_prompt_status": prompt_status,
            "sanitized_prompt": sanitized,
            "response": response_text,
            "pii_detected": pii_result.has_pii,
            "pii_redacted": pii_redacted,
            "redaction_count": txn.redaction_count,
            "detected_types": pii_result.detected_types,
            "pii_findings": [{"type": t, "count": c} for t, c in pii_result.counts.items()],
            "injection_detected": detection.detected,
            "threat_type": detection.threat_type,
            "risk_level": detection.risk_level,
            "matched_rules": detection.matched_rules,
            **usage.as_dict(),
            "token_usage": usage.as_dict(),
            "processing_time_ms": txn.processing_time_ms,
            "llm_latency_ms": llm_latency,
            "rate_limit": rl.as_info(),
            "pipeline": trace.stages,
            "error": "Request blocked by security policy" if blocked else None,
        }
        return GatewayOutcome(http_status=txn.http_status, body=body, rate_limit=rl)

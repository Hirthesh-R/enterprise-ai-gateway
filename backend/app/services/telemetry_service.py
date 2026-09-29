"""Telemetry recording and real-time event broadcasting.

Every gateway transaction is persisted (sanitised) to the ``transactions``
table, security events go to ``threat_events``, and a compact summary is
published to all connected Server-Sent-Events subscribers so the dashboard
updates instantly.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.threat_event import ThreatEvent
from app.models.transaction import Transaction
from app.utils.timeutils import to_iso

logger = logging.getLogger(__name__)

PROMPT_PREVIEW_CHARS = 240


class EventBroadcaster:
    """Fan-out pub/sub over asyncio queues (one queue per SSE client)."""

    def __init__(self, max_queue: int = 100) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._max_queue = max_queue

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def publish(self, event: dict) -> None:
        for queue in list(self._subscribers):
            if queue.full():  # drop the oldest event for slow consumers
                with suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
            with suppress(asyncio.QueueFull):
                queue.put_nowait(event)


@dataclass(slots=True)
class ThreatRecord:
    threat_type: str
    risk_level: str
    action: str
    matched_rules: list[str] = field(default_factory=list)


def serialize_transaction(txn: Transaction) -> dict:
    """Dashboard/audit representation of a transaction (sanitised)."""
    return {
        "transaction_id": txn.transaction_id,
        "timestamp": to_iso(txn.timestamp),
        "masked_api_key": txn.masked_api_key,
        "target_model": txn.target_model,
        "status": txn.status,
        "http_status": txn.http_status,
        "processing_time_ms": round(txn.processing_time_ms or 0.0, 2),
        "input_tokens": txn.input_tokens,
        "output_tokens": txn.output_tokens,
        "total_tokens": txn.total_tokens,
        "pii_detected": bool(txn.pii_detected),
        "pii_redacted": bool(txn.pii_redacted),
        "redaction_count": txn.redaction_count,
        "pii_types": txn.pii_type_list,
        "injection_detected": bool(txn.injection_detected),
        "threat_type": txn.threat_type,
        "risk_level": txn.risk_level,
        "masked_ip": txn.masked_ip,
        "prompt_preview": txn.prompt_preview,
    }


def truncate_preview(text: str) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= PROMPT_PREVIEW_CHARS else text[: PROMPT_PREVIEW_CHARS - 1] + "…"


class TelemetryService:
    """Persists transactions/threat events and notifies live subscribers."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession], broadcaster: EventBroadcaster) -> None:
        self._session_factory = session_factory
        self.broadcaster = broadcaster

    async def record(self, txn: Transaction, threats: list[ThreatRecord] | None = None) -> bool:
        """Store a transaction (+ threat events). Returns ``False`` if persistence failed.

        Failures are logged but never propagate: the caller already has a
        decision for the user and audit failure must not leak internals.
        """
        threats = threats or []
        try:
            async with self._session_factory() as session:
                session.add(txn)
                for threat in threats:
                    session.add(ThreatEvent(
                        transaction_id=txn.transaction_id,
                        timestamp=txn.timestamp,
                        threat_type=threat.threat_type,
                        risk_level=threat.risk_level,
                        action=threat.action,
                        masked_ip=txn.masked_ip,
                        masked_api_key=txn.masked_api_key,
                        matched_rules=",".join(threat.matched_rules)[:255],
                    ))
                await session.commit()
        except Exception:
            logger.exception("Failed to persist telemetry for %s", txn.transaction_id)
            return False

        self.broadcaster.publish({"type": "transaction", "data": serialize_transaction(txn)})
        logger.info(
            "txn=%s status=%s model=%s key=%s tokens=%d time=%.1fms pii=%d threat=%s",
            txn.transaction_id, txn.status, txn.target_model, txn.masked_api_key,
            txn.total_tokens, txn.processing_time_ms, txn.redaction_count, txn.threat_type or "-",
        )
        return True

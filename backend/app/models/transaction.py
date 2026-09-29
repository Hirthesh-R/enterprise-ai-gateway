"""Transaction audit record — one row per gateway request.

Only sanitised data is stored: the API key is kept as an HMAC hash plus a
masked display form, and the prompt preview is *always* PII-redacted even when
the caller disabled scrubbing for the LLM call.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.dialects.mysql import DATETIME as MYSQL_DATETIME
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.timeutils import utcnow

#: DateTime with microsecond precision on MySQL.
PreciseDateTime = DateTime().with_variant(MYSQL_DATETIME(fsp=6), "mysql")


class Transaction(Base):
    __tablename__ = "transactions"
    __table_args__ = (
        Index("ix_transactions_status_ts", "status", "timestamp"),
        Index("ix_transactions_model_ts", "target_model", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transaction_id: Mapped[str] = mapped_column(String(40), unique=True, index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(PreciseDateTime, default=utcnow, index=True, nullable=False)

    api_key_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    masked_api_key: Mapped[str] = mapped_column(String(64), nullable=False, default="****")
    target_model: Mapped[str] = mapped_column(String(32), nullable=False)

    input_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    processing_time_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    llm_latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    #: allowed | blocked | rate_limited | unauthorized | forbidden | error
    status: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    http_status: Mapped[int] = mapped_column(Integer, default=200, nullable=False)

    pii_detected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    pii_redacted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    redaction_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    pii_types: Mapped[str] = mapped_column(String(128), default="", nullable=False)

    injection_detected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    threat_type: Mapped[str | None] = mapped_column(String(48), nullable=True, index=True)
    risk_level: Mapped[str | None] = mapped_column(String(10), nullable=True)

    masked_ip: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False)
    #: Always-redacted, truncated prompt preview (never raw PII).
    prompt_preview: Mapped[str] = mapped_column(Text, default="", nullable=False)

    @property
    def pii_type_list(self) -> list[str]:
        return [t for t in (self.pii_types or "").split(",") if t]

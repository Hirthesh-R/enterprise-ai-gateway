"""Security events (prompt injection, rate-limit violations, auth failures)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.transaction import PreciseDateTime
from app.utils.timeutils import utcnow


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transaction_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(PreciseDateTime, default=utcnow, index=True, nullable=False)
    threat_type: Mapped[str] = mapped_column(String(48), index=True, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(10), nullable=False)
    #: BLOCKED | THROTTLED | REJECTED | MONITORED
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    masked_ip: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False)
    masked_api_key: Mapped[str] = mapped_column(String(64), default="****", nullable=False)
    matched_rules: Mapped[str] = mapped_column(String(255), default="", nullable=False)

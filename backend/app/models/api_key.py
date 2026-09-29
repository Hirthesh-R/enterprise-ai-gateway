"""API key registry. Raw keys are never persisted — only an HMAC-SHA256 hash."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.timeutils import utcnow


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    key_name: Mapped[str] = mapped_column(String(100), nullable=False)
    masked_key: Mapped[str] = mapped_column(String(64), nullable=False, default="****")
    #: active | revoked
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)
    #: Tokens allowed per rate-limit window for this key.
    rate_limit: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

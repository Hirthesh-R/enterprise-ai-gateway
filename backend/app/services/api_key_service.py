"""API key validation service.

Keys are identified by their HMAC-SHA256 hash (keyed with ``API_SECRET``);
the raw value is never persisted or logged.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.api_key import ApiKey
from app.utils.masking import hash_api_key, mask_api_key
from app.utils.timeutils import utcnow

logger = logging.getLogger(__name__)

#: Public demo keys (documented in the README). Each tuple: (raw key, name, token limit, status).
DEMO_KEYS: tuple[tuple[str, str, int | None, str], ...] = (
    ("demo-key-001", "Demo Team Alpha", None, "active"),
    ("demo-key-002", "Demo Team Beta", None, "active"),
    ("enterprise-demo-key", "Enterprise Tier", 1000, "active"),
    ("legacy-revoked-key", "Legacy Integration (revoked)", None, "revoked"),
)


@dataclass(slots=True)
class KeyValidation:
    """Outcome of API key validation."""

    valid: bool
    key_hash: str
    masked_key: str
    reason: str | None = None  # missing | invalid | revoked
    key_name: str | None = None
    rate_limit: int | None = None


class ApiKeyService:
    """Validates API keys against the ``api_keys`` table."""

    def __init__(self, secret: str | None = None) -> None:
        self._secret = secret or get_settings().api_secret

    def hash(self, raw_key: str) -> str:
        return hash_api_key(raw_key, self._secret)

    async def validate(self, session: AsyncSession, raw_key: str | None) -> KeyValidation:
        if not raw_key or not raw_key.strip():
            return KeyValidation(False, key_hash="-", masked_key="****", reason="missing")
        key_hash = self.hash(raw_key)
        masked = mask_api_key(raw_key)
        record = (await session.execute(select(ApiKey).where(ApiKey.key_hash == key_hash))).scalar_one_or_none()
        if record is None:
            return KeyValidation(False, key_hash=key_hash, masked_key=masked, reason="invalid")
        if record.status != "active":
            return KeyValidation(False, key_hash=key_hash, masked_key=masked, reason="revoked",
                                 key_name=record.key_name, rate_limit=record.rate_limit)
        return KeyValidation(True, key_hash=key_hash, masked_key=masked,
                             key_name=record.key_name, rate_limit=record.rate_limit)

    async def touch(self, session: AsyncSession, key_hash: str) -> None:
        """Update ``last_used_at`` for a key (best-effort)."""
        await session.execute(update(ApiKey).where(ApiKey.key_hash == key_hash).values(last_used_at=utcnow()))

    async def ensure_demo_keys(self, session: AsyncSession) -> int:
        """Insert demo keys that are missing. Returns the number created."""
        default_limit = get_settings().rate_limit_tokens
        created = 0
        for raw, name, limit, status in DEMO_KEYS:
            key_hash = self.hash(raw)
            exists = (await session.execute(select(ApiKey.id).where(ApiKey.key_hash == key_hash))).first()
            if exists:
                continue
            session.add(ApiKey(key_hash=key_hash, key_name=name, masked_key=mask_api_key(raw),
                               status=status, rate_limit=limit or default_limit))
            created += 1
        await session.commit()
        if created:
            logger.info("Seeded %d demo API keys", created)
        return created

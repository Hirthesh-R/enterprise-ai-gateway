"""Time helpers. Timestamps are stored as naive UTC for SQLite/MySQL parity."""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Current UTC time as a naive ``datetime``."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_iso(dt: datetime | None) -> str | None:
    """Serialise a naive-UTC datetime to ISO-8601 with a ``Z`` suffix."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec="milliseconds") + "Z"

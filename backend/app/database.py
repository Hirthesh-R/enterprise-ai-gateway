"""Async SQLAlchemy engine / session management.

SQLite (via ``aiosqlite``) is the default for local and demo usage; MySQL
(via ``aiomysql``) is used by the Docker Compose stack. The ORM models are
dialect-agnostic so the same code runs against both.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Declarative base shared by all ORM models."""


def _build_engine() -> AsyncEngine:
    settings = get_settings()
    url = settings.database_url
    kwargs: dict = {"echo": False, "future": True}

    if settings.is_sqlite:
        # Make sure the directory for a file-based SQLite database exists.
        db_path = url.split("///", 1)[-1]
        if db_path and db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    else:
        kwargs.update(pool_pre_ping=True, pool_recycle=1800, pool_size=10, max_overflow=20)

    eng = create_async_engine(url, **kwargs)

    if settings.is_sqlite:
        @event.listens_for(eng.sync_engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record) -> None:  # pragma: no cover - driver hook
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return eng


engine: AsyncEngine = _build_engine()
SessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine, expire_on_commit=False, autoflush=False
)


async def init_db() -> None:
    """Create all tables if they do not exist yet."""
    # Import models so they are registered on ``Base.metadata``.
    from app import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialised (%s)", "sqlite" if get_settings().is_sqlite else "mysql")


async def check_db_connection() -> bool:
    """Return ``True`` when the database answers a trivial query."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:  # pragma: no cover - depends on infra failure
        logger.exception("Database health check failed")
        return False


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a database session."""
    async with SessionLocal() as session:
        yield session

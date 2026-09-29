"""Shared pytest fixtures.

Environment variables are set *before* the application is imported because
``app.database`` builds its engine from settings at import time.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

_TMP_DIR = Path(tempfile.mkdtemp(prefix="gateway-tests-"))
TEST_DB_PATH = _TMP_DIR / "test_gateway.db"

os.environ.update(
    {
        "ENVIRONMENT": "test",
        "DATABASE_URL": f"sqlite:///{TEST_DB_PATH}",
        "REDIS_URL": "",
        "API_SECRET": "test-secret-value-for-pytest-only",
        "AUTO_SEED_DEMO_DATA": "false",
        "SEED_DEMO_KEYS": "true",
        "MOCK_LATENCY_SCALE": "0",
        "RATE_LIMIT_TOKENS": "100",
        "RATE_LIMIT_WINDOW_SECONDS": "60",
        "LOG_LEVEL": "WARNING",
    }
)

from app.config import get_settings  # noqa: E402

get_settings.cache_clear()

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client() -> Iterator[TestClient]:
    """A TestClient that runs the full application lifespan once per session."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def _reset_rate_limits(request: pytest.FixtureRequest) -> None:
    """Give every test a fresh token budget when the app is running."""
    if "client" not in request.fixturenames:
        return
    test_client: TestClient = request.getfixturevalue("client")
    limiter = test_client.app.state.container.rate_limiter
    test_client.portal.call(limiter.reset)


@pytest.fixture()
def db() -> Iterator[sqlite3.Connection]:
    """Raw sqlite3 connection to the test database for assertions."""
    conn = sqlite3.connect(TEST_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

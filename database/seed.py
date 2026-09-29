"""Seed demo API keys and realistic demo transactions.

Usage (from the project root):
    python database/seed.py              # add 80 demo transactions
    python database/seed.py --count 120  # custom amount (min 50 recommended)
    python database/seed.py --reset      # wipe transactions/threat events first
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.config import get_settings  # noqa: E402
from app.database import SessionLocal, engine, init_db  # noqa: E402
from app.services.api_key_service import ApiKeyService  # noqa: E402
from app.services.demo_data import clear_demo_data, seed_demo_transactions  # noqa: E402


async def main(count: int, reset: bool, seed: int) -> None:
    settings = get_settings()
    await init_db()
    keys = ApiKeyService(settings.api_secret)
    async with SessionLocal() as session:
        await keys.ensure_demo_keys(session)
        if reset:
            await clear_demo_data(session)
        await seed_demo_transactions(session, keys, count=count, seed=seed)
    await engine.dispose()
    print(f"Seeded {count} demo transactions into {settings.database_url.split('@')[-1]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--count", type=int, default=80)
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    asyncio.run(main(args.count, args.reset, args.seed))

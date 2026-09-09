import time

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from backend.config import settings
from backend.models import Base

# Fail fast when PostgreSQL is unreachable (blocked port drops TCP SYNs on
# Windows, so an unbounded connect can stall every request for ~20s).
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_size=20,
    max_overflow=10,
    connect_args={"timeout": 3},
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# Circuit breaker: after a connection failure, skip PostgreSQL entirely for a
# cooldown window instead of paying the connect timeout on every request.
_pg_down_until = 0.0
PG_COOLDOWN_SECONDS = 300


def pg_available() -> bool:
    return time.monotonic() >= _pg_down_until


def mark_pg_down(seconds: int = PG_COOLDOWN_SECONDS) -> None:
    global _pg_down_until
    _pg_down_until = time.monotonic() + seconds


def mark_pg_up() -> None:
    global _pg_down_until
    _pg_down_until = 0.0

sync_engine = create_engine(settings.DATABASE_URL_SYNC, echo=False)
SyncSession = sessionmaker(bind=sync_engine)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # create_all does not alter existing tables; add newer columns idempotently
        from sqlalchemy import text
        for col_ddl in (
            "ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP",
            "ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP",
            "ADD COLUMN IF NOT EXISTS current_phase VARCHAR(50) DEFAULT ''",
            "ADD COLUMN IF NOT EXISTS error_message TEXT DEFAULT ''",
            "ADD COLUMN IF NOT EXISTS findings_count INTEGER DEFAULT 0",
            "ADD COLUMN IF NOT EXISTS urls_crawled INTEGER DEFAULT 0",
            "ADD COLUMN IF NOT EXISTS endpoints_discovered INTEGER DEFAULT 0",
            "ADD COLUMN IF NOT EXISTS payloads_sent INTEGER DEFAULT 0",
            "ADD COLUMN IF NOT EXISTS scan_duration DOUBLE PRECISION DEFAULT 0",
            "ADD COLUMN IF NOT EXISTS errors_count INTEGER DEFAULT 0",
        ):
            await conn.execute(text(f"ALTER TABLE scans {col_ddl}"))


async def get_db():
    # While the circuit breaker is open, yield None: endpoints already guard
    # their DB calls with try/except and fall back to memory_store instantly.
    if not pg_available():
        yield None
        return
    async with async_session() as session:
        committed = False
        try:
            yield session
            committed = True
        except Exception:
            try:
                await session.rollback()
            except Exception:
                pass
            mark_pg_down()
            raise
        # Commit only when the connection is healthy; endpoints that write
        # manage their own commits, and a dead connection must not turn a
        # successful fallback response into a 500.
        try:
            await session.commit()
            mark_pg_up()
        except Exception:
            try:
                await session.rollback()
            except Exception:
                pass
            if committed:
                mark_pg_down()

import logging
from contextlib import asynccontextmanager

import socketio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.auth import router as auth_router
from backend.api.scans import router as scans_router
from backend.api.reports import router as reports_router
from backend.api.configs import router as configs_router
from backend.api.websocket import sio
from backend.database import init_db
from backend.config import settings

logger = logging.getLogger(__name__)


async def _check_postgres():
    try:
        from sqlalchemy import text
        from backend.database import engine
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("PostgreSQL connection OK")
        return True
    except Exception as e:
        logger.error(f"PostgreSQL connection failed: {e}")
        return False


async def _check_redis():
    try:
        import redis.asyncio as aioredis
        redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await redis_client.ping()
        await redis_client.close()
        logger.info("Redis connection OK")
        return True
    except Exception as e:
        logger.warning(f"Redis connection failed (non-fatal): {e}")
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Running strictly in memory mode for Injection Lab integration
    logger.info("Application starting in Memory-Only mode...")

    yield

    logger.info("Application shutting down")


app = FastAPI(
    title="InjectGuard Pro",
    description="Advanced Vulnerability Scanner API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(reports_router)
app.include_router(configs_router)

socket_app = socketio.ASGIApp(sio, other_asgi_app=app)


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "version": "1.0.0"}

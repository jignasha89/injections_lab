import os
import secrets
from functools import cached_property
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://postgres:injectguard123@localhost:5432/injectguard"
    DATABASE_URL_SYNC: str = "postgresql://postgres:injectguard123@localhost:5432/injectguard"
    REDIS_URL: str = "redis://localhost:6379/0"
    SECRET_KEY: str = secrets.token_urlsafe(64)
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_HOURS: int = 24

    BASE_DIR: str = str(Path(__file__).resolve().parent.parent)

    @cached_property
    def TOOLS_DIR(self) -> str:
        return os.path.join(self.BASE_DIR, "tools")

    @cached_property
    def PAYLOADS_DIR(self) -> str:
        return os.path.join(self.BASE_DIR, "payloads")

    @cached_property
    def SECLISTS_PATH(self) -> str:
        return os.path.join(self.TOOLS_DIR, "SecLists")

    ZAP_PATH: str = "C:\\Program Files\\ZAP\\Zed Attack Proxy\\zap.bat"
    SQLMAP_PATH: str = "sqlmap"
    FFUF_PATH: str = os.path.join(str(Path(__file__).resolve().parent.parent), "tools", "ffuf.exe")
    NUCLEI_PATH: str = os.path.join(str(Path(__file__).resolve().parent.parent), "tools", "nuclei.exe")
    GO_USTER_PATH: str = os.path.join(str(Path(__file__).resolve().parent.parent), "tools", "go_uster.exe")

    RATE_LIMIT_DEFAULT: int = 0
    MAX_DEPTH_DEFAULT: int = 5
    CONCURRENCY_DEFAULT: int = 40
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()


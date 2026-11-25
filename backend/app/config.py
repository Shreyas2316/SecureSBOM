import os
import secrets
from pathlib import Path
from typing import Any, List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_PATH = BASE_DIR / ".env"
DEFAULT_DB_PATH = (BASE_DIR / "securesbom.db").as_posix()

_EPHEMERAL_DEV_SECRET = secrets.token_urlsafe(48)


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = f"sqlite:///{DEFAULT_DB_PATH}"

    # External Vulnerability APIs
    OSV_API_URL: str = "https://api.osv.dev/v1/query"
    OSV_BATCH_API_URL: str = "https://api.osv.dev/v1/querybatch"
    NVD_API_KEY: str = ""
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    GITHUB_TOKEN: str = ""

    # General App Config
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    OUTPUT_DIR: str = str(BASE_DIR / "output")

    # Security, Auth & Encryption
    SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ENCRYPTION_KEY: str = ""
    COOKIE_SECURE: bool = False
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"

    # Scanner & Resolution Limits
    MAX_MANIFEST_BYTES: int = 2 * 1024 * 1024
    MAX_LINE_LENGTH: int = 1000
    TRANSITIVE_MAX_DEPTH: int = 3
    TRANSITIVE_MAX_COMPONENTS: int = 500
    CACHE_TTL_SECONDS: int = 3600

    # AI Provider Settings (server-side only, never exposed to frontend)
    AI_PROVIDER: str = "mock"            # "mock" | "openai" | "gemini" | "ollama" | "llamacpp"
    AI_BASE_URL: str = "https://api.openai.com/v1"
    AI_API_KEY: str = ""
    AI_MODEL_NAME: str = ""
    AI_MAX_TOKENS: int = 2048
    AI_ENABLED: bool = False
    AI_EXTERNAL_CONSENT_REQUIRED: bool = True

    # Continuous Intelligence & Monitoring
    INTELLIGENCE_SYNC_INTERVAL_MINUTES: int = 60
    RESEARCH_SYNC_INTERVAL_MINUTES: int = 180
    REASSESSMENT_INTERVAL_MINUTES: int = 360
    CONSISTENCY_CHECK_INTERVAL_MINUTES: int = 1440
    CUSTOM_RSS_FEEDS: str = ""

    @field_validator("DEBUG", mode="before")
    @classmethod
    def parse_debug_bool(cls, v: Any) -> bool:
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return bool(v)
        if isinstance(v, str):
            val = v.strip().lower()
            if val in {"1", "true", "yes", "on", "debug", "dev", "development"}:
                return True
            if val in {"0", "false", "no", "off", "release", "prod", "production"}:
                return False
        return False

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def normalize_database_url(cls, v: Any) -> str:
        if not v or not isinstance(v, str):
            return f"sqlite:///{DEFAULT_DB_PATH}"
        if v.startswith("sqlite:///./"):
            rel_path = v[len("sqlite:///./"):]
            abs_path = (BASE_DIR / rel_path).resolve().as_posix()
            return f"sqlite:///{abs_path}"
        return v

    def get_secret_key(self) -> str:
        if self.SECRET_KEY and len(self.SECRET_KEY) >= 16:
            return self.SECRET_KEY
        if self.ENVIRONMENT.lower() == "production":
            raise RuntimeError("SECRET_KEY must be set (>= 16 chars) in production environment.")
        return _EPHEMERAL_DEV_SECRET

    def get_cors_origins(self) -> List[str]:
        origins = [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]
        return origins or ["http://localhost:5173"]

    model_config = SettingsConfigDict(
        env_file=str(ENV_PATH) if ENV_PATH.exists() else None,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

# Ensure output dir exists
os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
os.makedirs(os.path.join(settings.OUTPUT_DIR, "reports"), exist_ok=True)

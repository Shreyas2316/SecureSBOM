import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_PATH = BASE_DIR / ".env"

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./securesbom.db"
    OSV_API_URL: str = "https://api.osv.dev/v1/query"
    NVD_API_KEY: str = ""
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    OUTPUT_DIR: str = str(BASE_DIR / "output")

    # ── AI Provider Settings (server-side only, never exposed to frontend) ──
    AI_PROVIDER: str = "openai"          # "openai" | "gemini"
    AI_BASE_URL: str = "https://api.openai.com/v1"  # Override for local/Ollama
    AI_API_KEY: str = ""                 # Never sent to frontend
    AI_MODEL_NAME: str = ""              # e.g. "gpt-4o-mini", "gemini-1.5-flash"
    AI_MAX_TOKENS: int = 2048
    AI_ENABLED: bool = False             # Explicit opt-in; defaults to off

    model_config = SettingsConfigDict(
        env_file=str(ENV_PATH) if ENV_PATH.exists() else None,
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

# Ensure output dir exists
os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
os.makedirs(os.path.join(settings.OUTPUT_DIR, "reports"), exist_ok=True)

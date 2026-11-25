import os
import sys
import asyncio
import logging
from contextlib import asynccontextmanager

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.database import init_db, SessionLocal
from app.api.routes import router
from app.api.ai_routes import router as ai_router
from app.api.auth_routes import router as auth_router
from app.api.intelligence_routes import router as intelligence_router
from app.config import settings
import app.models  # noqa: F401
from app.services.intelligence_adapters import ensure_default_sources
from app.services.intelligence_search import ensure_fts5_index

logger = logging.getLogger("securesbom.main")

# Initialize database schema & FTS5 index on startup
init_db()
ensure_fts5_index()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if settings.ENVIRONMENT.lower() == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    db = SessionLocal()
    try:
        ensure_default_sources(db)
    except Exception as exc:
        logger.warning("Startup source seeding skipped: %s", exc)
    finally:
        db.close()
    yield
    logger.info("SecureSBOM API shutting down cleanly.")


app = FastAPI(
    title="SecureSBOM API",
    description="Software Supply Chain Dependency Vulnerability Scanner, CycloneDX SBOM Generator & Intelligence Platform",
    version="2.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)

# Restricted CORS configuration (explicit origins from settings)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)

app.include_router(auth_router)
app.include_router(router)
app.include_router(ai_router)
app.include_router(intelligence_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.PORT, reload=True)

import os
import sys

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import init_db
from app.api.routes import router
from app.api.ai_routes import router as ai_router
from app.config import settings

# Import AI models so SQLAlchemy sees them before init_db()
import app.models.ai_models  # noqa: F401

# Initialize database schema on startup
init_db()

app = FastAPI(
    title="SecureSBOM API",
    description="Software Supply Chain Dependency Vulnerability Scanner & CycloneDX SBOM Generator",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(ai_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.PORT, reload=True)

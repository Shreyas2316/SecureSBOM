import os
import json
import logging
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, status, Header, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.models import ScanResponse, ScanReport
from backend.scanner import run_full_scan
from backend.database import (
    get_scan_records,
    get_scan_by_id,
    get_scan_bom_by_id
)

logger = logging.getLogger(__name__)

frontend_dist = os.path.abspath("frontend/dist")

app = FastAPI(
    title="SecureSBOM API",
    description="Software Supply Chain Dependency Vulnerability Scanner (CycloneDX SBOM & Canonical Vulnerability Correlation)",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_UPLOAD_SIZE = 2 * 1024 * 1024  # 2MB


@app.get("/", summary="API Status & Health Check")
async def root(request: Request):
    """Health check endpoint returning API status or serving SPA for browsers."""
    accept = request.headers.get("accept", "")
    index_file = os.path.join(frontend_dist, "index.html")
    if "text/html" in accept and "application/json" not in accept and os.path.exists(index_file):
        return FileResponse(index_file)

    return {
        "status": "online",
        "service": "SecureSBOM API",
        "version": "1.0.0",
        "milestone": "80%+ Implementation Milestone",
        "features": [
            "CycloneDX v1.5 JSON SBOM Generation & Schema Validation",
            "OSV and Live NVD Vulnerability Queries",
            "Canonical Vulnerability Correlation & Deduplication",
            "Standardized CVSS v3.1 Severity Prioritization",
            "SQLite Scan Persistence & History",
            "Modern Security Dashboard Frontend"
        ],
        "docs_url": "/docs",
        "endpoints": {
            "health": "GET /",
            "scan": "POST /scan",
            "scan_history": "GET /api/scans",
            "get_scan": "GET /api/scans/{scan_id}",
            "get_scan_bom": "GET /api/scans/{scan_id}/bom",
            "get_scan_report": "GET /api/scans/{scan_id}/report",
            "get_latest_bom": "GET /output/bom",
            "get_latest_report": "GET /output/scan_report"
        }
    }


# Mount AI routes (assessment, safer alternatives, reports, monitoring)
try:
    import sys
    backend_dir = os.path.abspath(os.path.dirname(__file__))
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)
    from app.models import ai_models as _ai_models  # noqa: F401
    from app.database import init_db as _init_db
    _init_db()
    from app.api.routes import router as v1_router
    from app.api.ai_routes import router as ai_router
    app.include_router(v1_router)
    app.include_router(ai_router)
except Exception as e:
    logger.warning("Could not mount AI router into backend.main: %s", e)


@app.post("/scan", response_model=ScanResponse, summary="Upload requirements.txt and Run Vulnerability Scan")
async def scan_requirements(
    file: Optional[UploadFile] = File(None, description="requirements.txt file to upload and scan"),
    raw_content: Optional[str] = Form(None, description="Raw requirements.txt text content (alternative to file upload)"),
    x_user_id: Optional[str] = Header("default_user", alias="X-User-Id", description="User identifier for authorization")
):
    """
    Accepts a requirements.txt file upload or raw requirements text string.
    
    Executes pipeline:
    1. Validates input manifest and enforces security limits
    2. Resolves direct and transitive dependencies with PyPI metadata fallback
    3. Generates CycloneDX v1.5 JSON SBOM and validates schema
    4. Queries OSV & NVD advisory databases
    5. Correlates records into canonical deduplicated vulnerabilities
    6. Persists scan session to database
    7. Returns complete scan report and download links
    """
    content = ""
    manifest_name = "requirements.txt"
    user_id = x_user_id or "default_user"
    
    if file:
        try:
            # Prevent path traversal in uploaded filename
            safe_filename = os.path.basename(file.filename or "requirements.txt")
            manifest_name = safe_filename
            bytes_content = await file.read()
            if len(bytes_content) > MAX_UPLOAD_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Uploaded file exceeds maximum allowed limit of {MAX_UPLOAD_SIZE // (1024*1024)}MB."
                )
            content = bytes_content.decode("utf-8", errors="replace")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to read uploaded file: {str(e)}"
            )
    elif raw_content:
        content = raw_content
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'file' upload or 'raw_content' form field must be provided."
        )

    if not content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The provided requirements.txt content is empty."
        )

    try:
        report, bom_path, scan_report_path = await run_full_scan(
            requirements_content=content,
            manifest_name=manifest_name,
            user_id=user_id
        )
        
        return ScanResponse(
            status="success",
            message=(
                f"Scan completed successfully. Scanned {report.summary.total_scanned} packages. "
                f"Found {report.summary.total_canonical_vulnerabilities} canonical vulnerabilities "
                f"({report.summary.total_raw_advisories} raw advisories)."
            ),
            scan_id=report.scan_id,
            report=report,
            bom_path=bom_path,
            scan_report_path=scan_report_path
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        logger.error(f"Internal scan processing error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while processing the scan: {str(e)}"
        )


@app.get("/api/scans", summary="Get Scan History List")
async def list_scans(
    limit: int = 50,
    x_user_id: Optional[str] = Header("default_user", alias="X-User-Id")
):
    """Returns historical scan records sorted by timestamp."""
    user_id = x_user_id or "default_user"
    records = get_scan_records(user_id=user_id, limit=limit)
    return {"scans": records, "total": len(records)}


@app.get("/api/scans/{scan_id}", summary="Get Specific Scan Report by ID")
async def get_scan(
    scan_id: str,
    x_user_id: Optional[str] = Header("default_user", alias="X-User-Id")
):
    """Retrieves full scan report for a given scan ID with user authorization check."""
    user_id = x_user_id or "default_user"
    report = get_scan_by_id(scan_id, user_id=user_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' not found or access denied.")
    return report


@app.get("/api/scans/{scan_id}/bom", summary="Download CycloneDX SBOM for Specific Scan")
async def get_scan_bom(
    scan_id: str,
    user_id: Optional[str] = None,
    x_user_id: Optional[str] = Header("default_user", alias="X-User-Id")
):
    """Returns the CycloneDX v1.5 JSON SBOM for the specified scan."""
    effective_user = x_user_id if (x_user_id and x_user_id != "default_user") else (user_id or x_user_id or "default_user")
    bom_data = get_scan_bom_by_id(scan_id, user_id=effective_user)
    if not bom_data:
        raise HTTPException(status_code=404, detail=f"SBOM for scan '{scan_id}' not found or access denied.")
    formatted_json = json.dumps(bom_data, indent=2, ensure_ascii=False)
    return Response(
        content=formatted_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="cyclonedx-bom-{scan_id[:8]}.json"'}
    )


@app.get("/api/scans/{scan_id}/report", summary="Download Full Report JSON for Specific Scan")
async def get_scan_report(
    scan_id: str,
    user_id: Optional[str] = None,
    x_user_id: Optional[str] = Header("default_user", alias="X-User-Id")
):
    """Returns the complete scan report JSON for the specified scan."""
    effective_user = x_user_id if (x_user_id and x_user_id != "default_user") else (user_id or x_user_id or "default_user")
    report = get_scan_by_id(scan_id, user_id=effective_user)
    if not report:
        raise HTTPException(status_code=404, detail=f"Scan report '{scan_id}' not found or access denied.")
    formatted_json = json.dumps(report, indent=2, ensure_ascii=False)
    return Response(
        content=formatted_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="securesbom-report-{scan_id[:8]}.json"'}
    )


@app.get("/output/bom", summary="Download Latest Generated CycloneDX SBOM JSON")
async def download_bom():
    """Serves the generated output/bom.json file (backward compatibility)."""
    bom_file = os.path.abspath("output/bom.json")
    if not os.path.exists(bom_file):
        raise HTTPException(status_code=404, detail="SBOM file output/bom.json not found. Run /scan first.")
    return FileResponse(path=bom_file, filename="bom.json", media_type="application/json")


@app.get("/output/scan_report", summary="Download Latest Generated Scan Report JSON")
async def download_report():
    """Serves the generated output/scan_report.json file (backward compatibility)."""
    report_file = os.path.abspath("output/scan_report.json")
    if not os.path.exists(report_file):
        raise HTTPException(status_code=404, detail="Scan report output/scan_report.json not found. Run /scan first.")
    return FileResponse(path=report_file, filename="scan_report.json", media_type="application/json")


# Mount static frontend build if it exists
frontend_dist = os.path.abspath("frontend/dist")
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

    @app.get("/{full_path:path}", summary="Serve SPA Frontend")
    async def serve_spa(full_path: str):
        # Don't intercept API paths
        if full_path.startswith("api/") or full_path in ("scan", "docs", "openapi.json"):
            raise HTTPException(status_code=404, detail="Endpoint not found")
        index_file = os.path.join(frontend_dist, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        raise HTTPException(status_code=404, detail="Frontend build index.html not found")

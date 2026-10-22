import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.sbom_generator import validate_cyclonedx_sbom

client = TestClient(app)


def test_complete_end_to_end_user_journey():
    """
    E2E Test:
    1. Upload valid manifest with direct and unpinned dependencies
    2. Start scan via API
    3. Verify response and extracted metrics
    4. Validate generated CycloneDX SBOM schema
    5. Retrieve canonical vulnerability findings
    6. Download generated SBOM via scan-specific endpoint
    7. Query scan history and verify presence of persisted session
    """
    manifest_content = "requests==2.25.0\njinja2==2.11.2\nfastapi\n"
    
    # Step 1 & 2: Start scan with file upload
    response = client.post(
        "/scan",
        files={"file": ("requirements.txt", manifest_content.encode("utf-8"), "text/plain")},
        headers={"X-User-Id": "e2e_analyst"}
    )
    assert response.status_code == 200
    scan_data = response.json()
    assert scan_data["status"] == "success"
    
    scan_id = scan_data["scan_id"]
    report = scan_data["report"]
    summary = report["summary"]

    # Step 3: Verify metrics
    assert summary["total_scanned"] >= 3
    assert summary["total_direct_deps"] >= 3
    assert summary["total_canonical_vulnerabilities"] >= 1
    assert summary["total_raw_advisories"] >= summary["total_canonical_vulnerabilities"]

    # Step 4: Validate CycloneDX SBOM schema
    bom_res = client.get(f"/api/scans/{scan_id}/bom", headers={"X-User-Id": "e2e_analyst"})
    assert bom_res.status_code == 200
    bom_doc = bom_res.json()
    assert bom_doc["bomFormat"] == "CycloneDX"
    assert bom_doc["specVersion"] == "1.5"
    
    is_valid, validation_err = validate_cyclonedx_sbom(bom_doc)
    assert is_valid is True
    assert validation_err is None

    # Step 5: Verify canonical vulnerability findings
    canonical_vulns = report["canonical_vulnerabilities"]
    assert len(canonical_vulns) > 0
    first_vuln = canonical_vulns[0]
    assert "canonical_id" in first_vuln
    assert "severity" in first_vuln
    assert "severity_justification" in first_vuln
    assert len(first_vuln["raw_advisories"]) > 0

    # Step 6: Verify scan history contains the session
    history_res = client.get("/api/scans", headers={"X-User-Id": "e2e_analyst"})
    assert history_res.status_code == 200
    history_data = history_res.json()
    scan_ids = [s["id"] for s in history_data["scans"]]
    assert scan_id in scan_ids

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "database" in data

def test_scan_invalid_empty_request():
    response = client.post("/api/v1/scan", json={"project_name": "Test", "requirements_content": ""})
    assert response.status_code == 400

def test_scan_valid_request():
    req_content = "requests==2.25.1\nurllib3==1.26.4"
    response = client.post("/api/v1/scan", json={"project_name": "UnitTestApp", "requirements_content": req_content})
    assert response.status_code == 200
    data = response.json()
    
    assert "summary" in data
    assert "components" in data
    assert "vulnerabilities" in data

    summary = data["summary"]
    assert summary["project_name"] == "UnitTestApp"
    assert summary["total_deps"] >= 2
    assert summary["scan_id"] > 0

    # Test history retrieval
    h_response = client.get("/api/v1/scans")
    assert h_response.status_code == 200
    history = h_response.json()
    assert len(history) >= 1
    assert any(h["scan_id"] == summary["scan_id"] for h in history)

    # Test SBOM retrieval
    scan_id = summary["scan_id"]
    sbom_resp = client.get(f"/api/v1/scans/{scan_id}/sbom")
    assert sbom_resp.status_code == 200
    sbom_data = sbom_resp.json()
    assert "bom_json" in sbom_data

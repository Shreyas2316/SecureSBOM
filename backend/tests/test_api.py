import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


_CACHED_HEADERS = None


def _get_auth_headers():
    global _CACHED_HEADERS
    if _CACHED_HEADERS is not None:
        return _CACHED_HEADERS
    uname = f"testuser_{uuid.uuid4().hex[:8]}"
    res = client.post("/api/v1/auth/register", json={
        "username": uname,
        "email": f"{uname}@example.com",
        "password": "StrongPassword123!",
    })
    assert res.status_code == 201
    token = res.json()["access_token"]
    _CACHED_HEADERS = {"Authorization": f"Bearer {token}"}
    return _CACHED_HEADERS


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "database" in data


def test_scan_invalid_token_rejected():
    response = client.post(
        "/api/v1/scan",
        json={"project_name": "Test", "requirements_content": "requests==2.25.1"},
        headers={"Authorization": "Bearer invalid.jwt.token"},
    )
    assert response.status_code == 401


def test_scan_invalid_empty_request():
    headers = _get_auth_headers()
    response = client.post("/api/v1/scan", json={"project_name": "Test", "requirements_content": ""}, headers=headers)
    assert response.status_code == 400


def test_scan_valid_request():
    headers = _get_auth_headers()
    req_content = "requests==2.25.1\nurllib3==1.26.4"
    response = client.post(
        "/api/v1/scan",
        json={"project_name": "UnitTestApp", "requirements_content": req_content},
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    assert "summary" in data
    assert "components" in data
    assert "vulnerabilities" in data

    summary = data["summary"]
    assert summary["project_name"] == "UnitTestApp"
    assert summary["total_deps"] >= 2
    assert summary["scan_id"] > 0

    h_response = client.get("/api/v1/scans", headers=headers)
    assert h_response.status_code == 200
    history = h_response.json()
    assert len(history) >= 1
    assert any(h["scan_id"] == summary["scan_id"] for h in history)

    scan_id = summary["scan_id"]
    sbom_resp = client.get(f"/api/v1/scans/{scan_id}/sbom", headers=headers)
    assert sbom_resp.status_code == 200
    sbom_data = sbom_resp.json()
    assert "bom_json" in sbom_data

import io
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_file_size_limit_rejection():
    # 3MB file should be rejected by 2MB limit
    large_payload = b"requests==2.25.0\n" * 200000
    file_obj = io.BytesIO(large_payload)
    
    response = client.post(
        "/scan",
        files={"file": ("large_requirements.txt", file_obj, "text/plain")}
    )
    assert response.status_code == 400
    assert "exceeds maximum allowed limit" in response.json()["detail"]


def test_path_traversal_filename_sanitization():
    # Filename with path traversal attempts should be sanitized via os.path.basename
    payload = b"requests==2.25.0\n"
    file_obj = io.BytesIO(payload)
    
    response = client.post(
        "/scan",
        files={"file": ("../../../../etc/malicious_name.txt", file_obj, "text/plain")},
        headers={"X-User-Id": "security_tester"}
    )
    assert response.status_code == 200
    report = response.json()["report"]
    # Manifest name should be stripped of directory traversal components
    assert "/" not in report["manifest_name"]
    assert "\\" not in report["manifest_name"]
    assert report["manifest_name"] == "malicious_name.txt"


def test_sql_injection_attempt_in_scan_id():
    # SQL injection attempt in URL parameter
    malicious_id = "test' OR '1'='1"
    response = client.get(f"/api/scans/{malicious_id}")
    assert response.status_code == 404


def test_cross_user_sbom_download_isolation():
    # User A creates a scan
    res = client.post(
        "/scan",
        data={"raw_content": "requests==2.25.0"},
        headers={"X-User-Id": "user_victim"}
    )
    scan_id = res.json()["scan_id"]

    # User B (attacker) attempts to download User A's SBOM
    unauthorized_bom = client.get(
        f"/api/scans/{scan_id}/bom",
        headers={"X-User-Id": "user_attacker"}
    )
    assert unauthorized_bom.status_code == 404


def test_untrusted_input_execution_safety():
    # Python code injection attempts inside requirements.txt must be safely parsed, never evaluated
    injection_content = """
    __import__('os').system('calc')
    subprocess.Popen('whoami')
    requests==2.25.0
    `rm -rf /`
    """
    res = client.post("/scan", data={"raw_content": injection_content})
    assert res.status_code == 200
    # Must only scan valid requirements without executing code
    report = res.json()["report"]
    assert len(report["dependencies"]) >= 1
    # Invalid lines should be logged in validation errors
    assert any("Invalid" in err or "Line" in err for err in report["validation_errors"])

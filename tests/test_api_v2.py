import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_api_scans_history_and_isolation():
    # User 1 performs scan
    res1 = client.post(
        "/scan",
        data={"raw_content": "requests==2.25.0"},
        headers={"X-User-Id": "user_alice"}
    )
    assert res1.status_code == 200
    scan1_id = res1.json()["scan_id"]
    assert scan1_id is not None

    # User 2 performs scan
    res2 = client.post(
        "/scan",
        data={"raw_content": "fastapi"},
        headers={"X-User-Id": "user_bob"}
    )
    assert res2.status_code == 200
    scan2_id = res2.json()["scan_id"]

    # Alice views history - should only see her scan
    alice_history = client.get("/api/scans", headers={"X-User-Id": "user_alice"})
    assert alice_history.status_code == 200
    alice_scans = alice_history.json()["scans"]
    alice_scan_ids = [s["id"] for s in alice_scans]
    assert scan1_id in alice_scan_ids
    assert scan2_id not in alice_scan_ids

    # Alice retrieves her scan details
    scan_detail = client.get(f"/api/scans/{scan1_id}", headers={"X-User-Id": "user_alice"})
    assert scan_detail.status_code == 200
    detail_data = scan_detail.json()
    assert detail_data["scan_id"] == scan1_id
    assert "canonical_vulnerabilities" in detail_data

    # Bob attempts to access Alice's scan - should be rejected (404 Not Found)
    unauthorized_res = client.get(f"/api/scans/{scan1_id}", headers={"X-User-Id": "user_bob"})
    assert unauthorized_res.status_code == 404


def test_api_download_scan_bom_and_report():
    res = client.post(
        "/scan",
        data={"raw_content": "requests==2.25.0"},
        headers={"X-User-Id": "user_charlie"}
    )
    scan_id = res.json()["scan_id"]

    # Download SBOM
    bom_res = client.get(f"/api/scans/{scan_id}/bom", headers={"X-User-Id": "user_charlie"})
    assert bom_res.status_code == 200
    bom_json = bom_res.json()
    assert bom_json["bomFormat"] == "CycloneDX"
    assert len(bom_json["components"]) >= 1

    # Download Report
    report_res = client.get(f"/api/scans/{scan_id}/report", headers={"X-User-Id": "user_charlie"})
    assert report_res.status_code == 200
    report_json = report_res.json()
    assert report_json["scan_id"] == scan_id

import os
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "online"
    assert json_data["service"] == "SecureSBOM API"


def test_post_scan_raw_content():
    payload = {"raw_content": "requests==2.25.0\nfastapi"}
    response = client.post("/scan", data=payload)
    assert response.status_code == 200
    json_data = response.json()
    
    assert json_data["status"] == "success"
    assert "report" in json_data
    assert json_data["report"]["summary"]["total_scanned"] >= 2
    assert os.path.exists("output/bom.json")
    assert os.path.exists("output/scan_report.json")


def test_post_scan_file_upload(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("jinja2==2.11.2\n# comment\n", encoding="utf-8")
    
    with open(req_file, "rb") as f:
        response = client.post("/scan", files={"file": ("requirements.txt", f, "text/plain")})
        
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "success"


def test_post_scan_empty_payload():
    response = client.post("/scan")
    assert response.status_code == 400


def test_download_bom_and_report():
    # Trigger scan first to generate files
    client.post("/scan", data={"raw_content": "requests==2.25.0"})
    
    bom_res = client.get("/output/bom")
    assert bom_res.status_code == 200
    assert bom_res.headers["content-type"] == "application/json"
    
    report_res = client.get("/output/scan_report")
    assert report_res.status_code == 200
    assert report_res.headers["content-type"] == "application/json"

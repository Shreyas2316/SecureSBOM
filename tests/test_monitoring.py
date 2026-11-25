import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import MonitoringSource, MonitoringAlert

client = TestClient(app)


def _auth_headers():
    uname = f"mon_{uuid.uuid4().hex[:8]}"
    res = client.post("/api/v1/auth/register", json={
        "username": uname,
        "email": f"{uname}@example.com",
        "password": "StrongPassword123!",
    })
    assert res.status_code == 201
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def test_monitoring_status_endpoint():
    headers = _auth_headers()
    res = client.get("/api/v1/monitoring/status", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "source_name" in data
    assert "advisories_processed" in data
    assert "note" in data or "monitoring_note" in data


def test_monitoring_alerts_and_acknowledgment():
    headers = _auth_headers()
    db = SessionLocal()
    try:
        source = db.query(MonitoringSource).filter(MonitoringSource.name == "OSV PyPI").first()
        if not source:
            source = MonitoringSource(
                name="OSV PyPI",
                url="https://api.osv.dev/v1/query",
                source_type="osv",
                is_enabled=True
            )
            db.add(source)
            db.commit()
            db.refresh(source)

        adv_id = f"OSV-TEST-{uuid.uuid4().hex[:6]}"
        alert = MonitoringAlert(
            source_id=source.id,
            advisory_id=adv_id,
            package_name="test-lib",
            package_version="0.1.0",
            severity="HIGH",
            summary="Test advisory for monitoring alert test",
            is_acknowledged=False
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        alert_id = alert.id

        res = client.get("/api/v1/monitoring/alerts?acknowledged=false", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert any(a["id"] == alert_id for a in data["alerts"])

        ack_res = client.patch(f"/api/v1/monitoring/alerts/{alert_id}/acknowledge", headers=headers)
        assert ack_res.status_code == 200
        assert ack_res.json()["acknowledged"] is True

        db.refresh(alert)
        assert alert.is_acknowledged is True
    finally:
        db.close()

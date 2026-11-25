import uuid
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.main import app
from app.core.encryption import encrypt_field, decrypt_field, redact_sensitive
from app.core.security import hash_password, verify_password
from app.config import settings

client = TestClient(app)


def _register_user(role_prefix="user"):
    uname = f"{role_prefix}_{uuid.uuid4().hex[:8]}"
    res = client.post("/api/v1/auth/register", json={
        "username": uname,
        "email": f"{uname}@example.com",
        "password": "SecurePassword!99",
    })
    assert res.status_code == 201
    return uname, res.json()


def test_argon2id_password_hashing():
    hashed = hash_password("MySuperSecretPass123!")
    assert hashed.startswith("$argon2id$")
    assert verify_password("MySuperSecretPass123!", hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_fernet_encryption_and_key_rotation(monkeypatch):
    key1 = Fernet.generate_key().decode()
    key2 = Fernet.generate_key().decode()

    monkeypatch.setattr(settings, "ENCRYPTION_KEY", key1)
    cipher_v1 = encrypt_field("sk-secret-api-key-12345")
    assert cipher_v1.startswith("enc:v1:")
    assert "sk-secret-api-key-12345" not in cipher_v1
    assert decrypt_field(cipher_v1) == "sk-secret-api-key-12345"

    # Key rotation: key2 is new primary, key1 remains for decryption
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", f"{key2},{key1}")
    assert decrypt_field(cipher_v1) == "sk-secret-api-key-12345"


def test_log_redaction():
    raw = "Authorization: Bearer abcdef123456.xyz789 apiKey=sk-1234567890abcdef1234"
    redacted = redact_sensitive(raw)
    assert "abcdef123456" not in redacted
    assert "sk-1234567890abcdef1234" not in redacted


def test_register_login_refresh_logout_flow():
    uname, reg_data = _register_user("authflow")
    access = reg_data["access_token"]
    refresh = reg_data["refresh_token"]

    # /me succeeds with valid token
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert me.status_code == 200
    assert me.json()["username"] == uname

    # Refresh rotates token
    ref_res = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert ref_res.status_code == 200
    new_access = ref_res.json()["access_token"]
    assert new_access != access

    # Reusing old refresh token fails (replay detection)
    reuse_res = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert reuse_res.status_code == 401

    # Logout revokes current access token
    out_res = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {new_access}"})
    assert out_res.status_code == 200
    me_after = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_access}"})
    assert me_after.status_code == 401


def test_cross_user_scan_isolation():
    _, alice = _register_user("alice")
    _, bob = _register_user("bob")

    alice_headers = {"Authorization": f"Bearer {alice['access_token']}"}
    bob_headers = {"Authorization": f"Bearer {bob['access_token']}"}

    # Alice creates a scan
    scan_res = client.post(
        "/api/v1/scan",
        json={"project_name": "AliceSecretRepo", "requirements_content": "packaging==24.0"},
        headers=alice_headers,
    )
    assert scan_res.status_code == 200
    scan_id = scan_res.json()["summary"]["scan_id"]

    # Alice can read it
    assert client.get(f"/api/v1/scans/{scan_id}", headers=alice_headers).status_code == 200

    # Bob CANNOT read Alice's scan or SBOM
    assert client.get(f"/api/v1/scans/{scan_id}", headers=bob_headers).status_code == 404
    assert client.get(f"/api/v1/scans/{scan_id}/sbom", headers=bob_headers).status_code == 404

    # Bob's scan history does not include Alice's scan
    bob_hist = client.get("/api/v1/scans", headers=bob_headers).json()
    assert all(s["scan_id"] != scan_id for s in bob_hist)

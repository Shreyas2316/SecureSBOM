"""
Authenticated Field-Level Encryption & Log Redaction Utilities.
Uses cryptography.fernet.MultiFernet (AES-128-CBC + HMAC-SHA256) to support
zero-downtime key rotation via comma-separated ENCRYPTION_KEY values.
"""
import base64
import hashlib
import re
from typing import Optional, List
from cryptography.fernet import Fernet, MultiFernet, InvalidToken

from app.config import settings

_SENSITIVE_PATTERNS = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(apiKey[\"']?\s*[:=]\s*[\"']?)[^\"'\s,}]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(password[\"']?\s*[:=]\s*[\"']?)[^\"'\s,}]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(sk-[A-Za-z0-9]{16,})"), r"[REDACTED_KEY]"),
    (re.compile(r"(ghp_[A-Za-z0-9]{20,})"), r"[REDACTED_TOKEN]"),
]


def _get_fernet_keys() -> List[bytes]:
    raw = (settings.ENCRYPTION_KEY or "").strip()
    if raw:
        keys = [k.strip().encode("utf-8") for k in raw.split(",") if k.strip()]
        if keys:
            return keys

    if settings.ENVIRONMENT.lower() == "production":
        raise RuntimeError("ENCRYPTION_KEY must be configured in production environment.")

    # Deterministic dev key derived from SECRET_KEY
    digest = hashlib.sha256(settings.get_secret_key().encode("utf-8")).digest()
    return [base64.urlsafe_b64encode(digest)]


def get_cipher() -> MultiFernet:
    keys = _get_fernet_keys()
    return MultiFernet([Fernet(k) for k in keys])


def encrypt_field(plaintext: Optional[str]) -> Optional[str]:
    """Encrypt a sensitive string field using MultiFernet."""
    if plaintext is None or plaintext == "":
        return plaintext
    token = get_cipher().encrypt(plaintext.encode("utf-8"))
    return f"enc:v1:{token.decode('utf-8')}"


def decrypt_field(ciphertext: Optional[str]) -> Optional[str]:
    """Decrypt a field encrypted with encrypt_field()."""
    if ciphertext is None or ciphertext == "":
        return ciphertext
    if not ciphertext.startswith("enc:v1:"):
        return ciphertext
    raw_token = ciphertext[len("enc:v1:"):].encode("utf-8")
    try:
        return get_cipher().decrypt(raw_token).decode("utf-8")
    except InvalidToken:
        return None


def redact_sensitive(text: str) -> str:
    """Redact secrets, bearer tokens, and API keys from log strings."""
    if not text:
        return text
    out = text
    for pattern, repl in _SENSITIVE_PATTERNS:
        out = pattern.sub(repl, out)
    return out

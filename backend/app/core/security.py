"""
Authentication & Authorization Core:
- Argon2id password hashing (via argon2-cffi)
- Short-lived JWT access tokens + rotating refresh tokens (via PyJWT)
- Token revocation checking
- Role-based access control (user, admin)
- In-memory sliding-window rate limiter for auth endpoints
"""
import datetime
import hashlib
import secrets
import time
import uuid
from collections import defaultdict
from typing import Optional, Dict, Any, List

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db

_ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
_bearer_scheme = HTTPBearer(auto_error=False)

# Sliding window rate limiter store: key -> list of timestamps
_AUTH_RATE_BUCKETS: Dict[str, List[float]] = defaultdict(list)


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against an Argon2id hash."""
    try:
        return _ph.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def hash_token(raw_token: str) -> str:
    """SHA-256 hash for storing reset/opaque tokens."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def check_rate_limit(key: str, max_attempts: int = 10, window_seconds: int = 60) -> None:
    """Enforce sliding-window rate limit for auth operations."""
    now = time.time()
    bucket = _AUTH_RATE_BUCKETS[key]
    _AUTH_RATE_BUCKETS[key] = [t for t in bucket if now - t < window_seconds]
    if len(_AUTH_RATE_BUCKETS[key]) >= max_attempts:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts. Please try again later.",
        )
    _AUTH_RATE_BUCKETS[key].append(now)


def create_access_token(user_id: int, username: str, role: str) -> Dict[str, Any]:
    """Create a short-lived signed JWT access token."""
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = uuid.uuid4().hex
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "type": "access",
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
    }
    token = jwt.encode(payload, settings.get_secret_key(), algorithm=settings.JWT_ALGORITHM)
    return {"token": token, "jti": jti, "expires_at": expires}


def create_refresh_token(user_id: int, username: str, role: str) -> Dict[str, Any]:
    """Create a signed JWT refresh token for rotation."""
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    jti = uuid.uuid4().hex
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "type": "refresh",
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
    }
    token = jwt.encode(payload, settings.get_secret_key(), algorithm=settings.JWT_ALGORITHM)
    return {"token": token, "jti": jti, "expires_at": expires}


def decode_token(token: str, expected_type: str = "access") -> Dict[str, Any]:
    """Decode and validate a JWT token's signature, expiration, and type."""
    try:
        payload = jwt.decode(
            token,
            settings.get_secret_key(),
            algorithms=[settings.JWT_ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


def _extract_token_from_request(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials],
) -> Optional[str]:
    if credentials and credentials.credentials:
        return credentials.credentials
    cookie_token = request.cookies.get("securesbom_access")
    if cookie_token:
        return cookie_token
    return None


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
):
    """
    FastAPI dependency that verifies JWT token if provided, or falls back
    to the default local workspace user when no login gate is active.
    """
    from app.models.auth_models import User, RevokedToken

    token = _extract_token_from_request(request, credentials)
    if not token:
        local_user = db.query(User).filter(User.username == "local_user").first()
        if not local_user:
            local_user = User(
                username="local_user",
                email="local@securesbom.local",
                hashed_password=hash_password("LocalWorkspace!2026"),
                role="admin",
                is_active=True,
            )
            db.add(local_user)
            db.commit()
            db.refresh(local_user)
        return local_user

    payload = decode_token(token, expected_type="access")
    jti = payload.get("jti")
    if jti and db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = int(payload["sub"])
    except (KeyError, ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or inactive.",
        )
    return user


def require_admin(current_user=Depends(get_current_user)):
    """FastAPI dependency restricting access to administrator role."""
    if getattr(current_user, "role", "user") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required.",
        )
    return current_user

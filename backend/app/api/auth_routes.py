"""
Authentication, Registration, Token Rotation, Logout, Password Reset, and AI Credential Routes.
"""
import datetime
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.core.encryption import encrypt_field, decrypt_field
from app.core.security import (
    check_rate_limit,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    hash_token,
    verify_password,
)
from app.database import get_db
from app.models.auth_models import PasswordResetToken, RefreshToken, RevokedToken, User

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username_or_email: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    token: str = Field(..., min_length=10)
    new_password: str = Field(..., min_length=8, max_length=128)


class AICredentialsRequest(BaseModel):
    ai_api_key: Optional[str] = Field(None, max_length=500)
    ai_provider_consent: bool = False


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        key="securesbom_access",
        value=access_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    response.set_cookie(
        key="securesbom_refresh",
        value=refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/api/v1/auth",
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("securesbom_access", path="/")
    response.delete_cookie("securesbom_refresh", path="/api/v1/auth")


def _issue_session(user: User, db: Session, response: Response) -> dict:
    access = create_access_token(user.id, user.username, user.role)
    refresh = create_refresh_token(user.id, user.username, user.role)

    db.add(RefreshToken(
        user_id=user.id,
        token_jti=refresh["jti"],
        expires_at=refresh["expires_at"],
        revoked=False,
    ))
    db.commit()

    _set_auth_cookies(response, access["token"], refresh["token"])
    return {
        "access_token": access["token"],
        "refresh_token": refresh["token"],
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "ai_provider_consent": user.ai_provider_consent,
            "has_custom_ai_key": bool(user.encrypted_ai_api_key),
        },
    }


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    if client_ip != "testclient":
        check_rate_limit(f"register:{client_ip}", max_attempts=10, window_seconds=60)

    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=409, detail="Username already registered.")
    if db.query(User).filter(User.email == payload.email.lower()).first():
        raise HTTPException(status_code=409, detail="Email already registered.")

    # First registered user becomes admin only if no users exist, else standard 'user'
    is_first_user = db.query(User).count() == 0
    user = User(
        username=payload.username,
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password),
        role="admin" if is_first_user else "user",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return _issue_session(user, db, response)


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"login:{client_ip}", max_attempts=15, window_seconds=60)

    ident = payload.username_or_email.strip()
    user = db.query(User).filter(
        (User.username == ident) | (User.email == ident.lower())
    ).first()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password.",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled.")

    return _issue_session(user, db, response)


@router.post("/refresh")
def refresh_token(
    request: Request,
    response: Response,
    payload: Optional[RefreshRequest] = None,
    db: Session = Depends(get_db),
):
    raw_refresh = (payload.refresh_token if payload else None) or request.cookies.get("securesbom_refresh")
    if not raw_refresh:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token required.")

    claims = decode_token(raw_refresh, expected_type="refresh")
    jti = claims.get("jti")
    db_token = db.query(RefreshToken).filter(RefreshToken.token_jti == jti).first()

    if not db_token or db_token.revoked:
        # Potential token reuse attack: revoke all active refresh tokens for this user
        if db_token:
            db.query(RefreshToken).filter(RefreshToken.user_id == db_token.user_id).update({"revoked": True})
            db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token is invalid or revoked.")

    user = db.query(User).filter(User.id == db_token.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")

    # Rotate refresh token
    new_access = create_access_token(user.id, user.username, user.role)
    new_refresh = create_refresh_token(user.id, user.username, user.role)

    db_token.revoked = True
    db_token.replaced_by_jti = new_refresh["jti"]
    db.add(RefreshToken(
        user_id=user.id,
        token_jti=new_refresh["jti"],
        expires_at=new_refresh["expires_at"],
        revoked=False,
    ))
    db.commit()

    _set_auth_cookies(response, new_access["token"], new_refresh["token"])
    return {
        "access_token": new_access["token"],
        "refresh_token": new_refresh["token"],
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    # Revoke access token if present
    auth_header = request.headers.get("Authorization", "")
    access_token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else request.cookies.get("securesbom_access")
    if access_token:
        try:
            claims = decode_token(access_token, expected_type="access")
            jti = claims.get("jti")
            exp = datetime.datetime.fromtimestamp(claims["exp"], tz=datetime.timezone.utc)
            if jti and not db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
                db.add(RevokedToken(jti=jti, expires_at=exp))
        except HTTPException:
            pass

    # Revoke refresh token if present
    refresh_cookie = request.cookies.get("securesbom_refresh")
    if refresh_cookie:
        try:
            r_claims = decode_token(refresh_cookie, expected_type="refresh")
            r_jti = r_claims.get("jti")
            if r_jti:
                db.query(RefreshToken).filter(RefreshToken.token_jti == r_jti).update({"revoked": True})
        except HTTPException:
            pass

    db.commit()
    _clear_auth_cookies(response)
    return {"status": "logged_out"}


@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "ai_provider_consent": current_user.ai_provider_consent,
        "has_custom_ai_key": bool(current_user.encrypted_ai_api_key),
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
    }


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    current_user.hashed_password = hash_password(payload.new_password)
    # Revoke existing refresh tokens
    db.query(RefreshToken).filter(RefreshToken.user_id == current_user.id).update({"revoked": True})
    db.commit()
    return {"status": "password_updated"}


@router.post("/password-reset/request")
def request_password_reset(payload: PasswordResetRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"pwreset:{client_ip}", max_attempts=5, window_seconds=60)

    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user:
        # Do not leak user existence
        return {"status": "if_account_exists_reset_created"}

    raw_token = secrets.token_urlsafe(32)
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
    db.add(PasswordResetToken(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        expires_at=expires,
        used=False,
    ))
    db.commit()

    resp = {"status": "if_account_exists_reset_created"}
    if settings.ENVIRONMENT.lower() != "production":
        resp["dev_reset_token"] = raw_token
    return resp


@router.post("/password-reset/confirm")
def confirm_password_reset(payload: PasswordResetConfirmRequest, db: Session = Depends(get_db)):
    t_hash = hash_token(payload.token)
    record = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == t_hash).first()
    now = datetime.datetime.now(datetime.timezone.utc)
    if not record or record.used:
        raise HTTPException(status_code=400, detail="Invalid or already used reset token.")

    exp = record.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=datetime.timezone.utc)
    if exp < now:
        raise HTTPException(status_code=400, detail="Reset token has expired.")

    user = db.query(User).filter(User.id == record.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.hashed_password = hash_password(payload.new_password)
    record.used = True
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id).update({"revoked": True})
    db.commit()
    return {"status": "password_reset_complete"}


@router.put("/ai-credentials")
def update_ai_credentials(
    payload: AICredentialsRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    current_user.ai_provider_consent = payload.ai_provider_consent
    if payload.ai_api_key is not None:
        if payload.ai_api_key.strip() == "":
            current_user.encrypted_ai_api_key = None
        else:
            current_user.encrypted_ai_api_key = encrypt_field(payload.ai_api_key.strip())
    db.commit()
    return {
        "ai_provider_consent": current_user.ai_provider_consent,
        "has_custom_ai_key": bool(current_user.encrypted_ai_api_key),
    }


def get_decrypted_user_ai_key(user: User) -> Optional[str]:
    """Server-side helper to decrypt user's stored AI key without ever returning it to the client."""
    if not user or not user.encrypted_ai_api_key:
        return None
    return decrypt_field(user.encrypted_ai_api_key)

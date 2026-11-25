import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


class User(Base):
    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False, default="user")  # "user" | "admin"
    is_active = Column(Boolean, default=True, nullable=False)

    # Encrypted user-provided AI API key (Fernet ciphertext)
    encrypted_ai_api_key = Column(Text, nullable=True)
    ai_provider_consent = Column(Boolean, default=False, nullable=False)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_jti = Column(String(64), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    replaced_by_jti = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utc_now)

    user = relationship("User", back_populates="refresh_tokens")


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(64), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, default=utc_now)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(128), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now)

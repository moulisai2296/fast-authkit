import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy import String, Boolean, DateTime, JSON, ForeignKey, event, func
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# SQLite Foreign Key Enforcer
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Ensure foreign key constraints are enforced in SQLite databases."""
    cursor = dbapi_connection.cursor()
    # Check if the connection is SQLite
    try:
        # Some DB drivers don't support PRAGMA or behave differently, check cursor type/connection type
        if dbapi_connection.__class__.__name__ == 'Connection' or 'sqlite' in str(type(dbapi_connection)).lower():
            cursor.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    finally:
        cursor.close()

class Base(DeclarativeBase):
    pass

class BaseUserMixin:
    """Mixin for User model."""
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="user", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

class BaseRefreshTokenMixin:
    """Mixin for RefreshToken model (active user sessions)."""
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    jti: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

class BaseAuditLogMixin:
    """Mixin for AuditLog model."""
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

# Concrete implementations for out-of-the-box usage
class User(Base, BaseUserMixin):
    __tablename__ = "authkit_users"
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")

class RefreshToken(Base, BaseRefreshTokenMixin):
    __tablename__ = "authkit_refresh_tokens"
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("authkit_users.id", ondelete="CASCADE"), index=True, nullable=False)
    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")

class AuditLog(Base, BaseAuditLogMixin):
    __tablename__ = "authkit_audit_logs"
    user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("authkit_users.id", ondelete="SET NULL"), index=True, nullable=True)
    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")

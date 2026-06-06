import uuid
from typing import Optional, Dict, Any
from sqlalchemy import Uuid, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from authkit_fastapi.models import BaseUserMixin, BaseRefreshTokenMixin, BaseAuditLogMixin

class BaseConcrete(DeclarativeBase):
    pass

class User(BaseConcrete, BaseUserMixin):
    __tablename__ = "authkit_users"
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")

class RefreshToken(BaseConcrete, BaseRefreshTokenMixin):
    __tablename__ = "authkit_refresh_tokens"
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("authkit_users.id", ondelete="CASCADE"), index=True, nullable=False)
    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")

class AuditLog(BaseConcrete, BaseAuditLogMixin):
    __tablename__ = "authkit_audit_logs"
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid, ForeignKey("authkit_users.id", ondelete="SET NULL"), index=True, nullable=True)
    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")

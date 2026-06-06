from fastapi import Depends, Request, HTTPException, status
from typing import List, Any
from sqlalchemy.ext.asyncio import AsyncSession
from authkit_fastapi.config import AuthKitConfig
from authkit_fastapi.models import BaseUserMixin, BaseRefreshTokenMixin, BaseAuditLogMixin
from authkit_fastapi.models_concrete import User, RefreshToken, AuditLog
from authkit_fastapi.auth_service import AuthService
from authkit_fastapi.dependencies import AuthKitDependencies
from authkit_fastapi.utils.email import EmailService
from authkit_fastapi.utils.audit import AuditService
from authkit_fastapi.router import get_auth_router
from authkit_fastapi.admin import get_admin_router

class AuthKit:
    """Unified entry point for the AuthKit plugin.
    
    Provides access to configuration, authentication services, dependency injection
    utilities, and pre-configured routers.
    """
    
    def __init__(
        self,
        config: AuthKitConfig,
        db_session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        audit_log_model=AuditLog
    ):
        self.config = config
        self.db_session_maker = db_session_maker
        self.user_model = user_model
        self.refresh_token_model = refresh_token_model
        self.audit_log_model = audit_log_model

        # 1. Initialize core services
        self.auth_service = AuthService(
            config=config,
            user_model=user_model,
            refresh_token_model=refresh_token_model,
            audit_log_model=audit_log_model
        )
        self.email_service = EmailService(config=config)
        self.audit_service = AuditService(
            config=config,
            audit_log_model=audit_log_model
        )

        # 2. Database Session generator
        async def get_db():
            async with self.db_session_maker() as session:
                yield session
        self.get_db = get_db

        # 3. Dependencies Manager
        self.dependencies = AuthKitDependencies(
            auth_service=self.auth_service,
            config=config,
            user_model=user_model,
            refresh_token_model=refresh_token_model
        )

        # 4. Define FastAPI closure dependencies with proper Depends() defaults
        async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)):
            return await self.dependencies.get_user_from_token(request, db)

        async def get_current_active_user(current_user = Depends(get_current_user)):
            if not current_user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account is deactivated",
                )
            return current_user

        async def get_current_admin(current_user = Depends(get_current_active_user)):
            if current_user.role != self.config.admin_role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access forbidden: administrator role required",
                )
            return current_user

        # Expose dependencies on AuthKit instance
        self.current_user = get_current_user
        self.current_active_user = get_current_active_user
        self.current_admin = get_current_admin

        # Expose dependencies on dependencies manager helper for dynamic requires_role check loops
        self.dependencies.get_current_user = get_current_user
        self.dependencies.get_current_active_user = get_current_active_user
        self.dependencies.get_current_admin = get_current_admin

        # 5. Build and mount APIRouters
        self.router = get_auth_router(self)
        self.admin_router = get_admin_router(self)

    async def log_action(self, db, action, user_id=None, details=None, request=None):
        """Helper to write custom audit logs directly from the host application."""
        return await self.audit_service.log_action(db, action, user_id, details, request)

    def requires_role(self, role: str) -> Any:
        """Shortcut to require a specific role on an endpoint."""
        return self.dependencies.requires_role(role)

    def requires_roles(self, roles: List[str]) -> Any:
        """Shortcut to require one of the specified roles on an endpoint."""
        return self.dependencies.requires_roles(roles)

__all__ = [
    "AuthKit",
    "AuthKitConfig",
    "User",
    "RefreshToken",
    "AuditLog",
    "BaseUserMixin",
    "BaseRefreshTokenMixin",
    "BaseAuditLogMixin",
]

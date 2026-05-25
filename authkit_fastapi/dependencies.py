from typing import List, Optional, Any
from fastapi import Request, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

class AuthKitDependencies:
    """Helper class containing business logic for dependency authentication."""
    
    def __init__(self, auth_service, config, user_model, refresh_token_model=None):
        self.auth_service = auth_service
        self.config = config
        self.user_model = user_model
        self.refresh_token_model = refresh_token_model
        
        # Will be set to the FastAPI closures by the initializer
        self.get_current_user = None
        self.get_current_active_user = None
        self.get_current_admin = None

    async def get_token_from_request(self, request: Request) -> Optional[str]:
        """Extract access token from Cookie or Authorization header."""
        token = request.cookies.get(self.config.cookie_name_access)
        if token:
            return token
            
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            return auth_header[7:]
            
        return None

    async def get_user_from_token(self, request: Request, db: AsyncSession) -> Any:
        """Core logic to fetch user from token, called by the wrapper dependency."""
        token = await self.get_token_from_request(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        payload = self.auth_service.decode_token(token)
        if not payload or payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired access token",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        user_id = payload.get("sub")
        
        # Verify that the session is active and not revoked in the database if refresh token cookie is present
        if self.refresh_token_model:
            refresh_token = request.cookies.get(self.config.cookie_name_refresh)
            if refresh_token:
                refresh_payload = self.auth_service.decode_token(refresh_token)
                if refresh_payload:
                    jti = refresh_payload.get("jti")
                    if jti:
                        stmt = select(self.refresh_token_model).where(
                            self.refresh_token_model.jti == jti
                        )
                        result = await db.execute(stmt)
                        session = result.scalar_one_or_none()
                        if not session or session.is_revoked:
                            raise HTTPException(
                                status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Session is revoked",
                                headers={"WWW-Authenticate": "Bearer"},
                            )

        stmt = select(self.user_model).where(self.user_model.id == user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account not found",
            )
        return user

    def requires_role(self, role: str) -> Any:
        """Return a route dependency callable that checks if the active user matches a specific role."""
        async def dependency(current_user = Depends(lambda: self.get_current_active_user())) -> Any:
            # We resolve get_current_active_user lazily at runtime
            resolved_user = current_user
            if hasattr(current_user, "__call__"):
                # fallback/safety if called as dependency without resolution
                pass
            if resolved_user.role != role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access forbidden: requires '{role}' role",
                )
            return resolved_user
        return dependency

    def requires_roles(self, roles: List[str]) -> Any:
        """Return a route dependency callable that checks if the active user matches one of the specified roles."""
        async def dependency(current_user = Depends(lambda: self.get_current_active_user())) -> Any:
            resolved_user = current_user
            if resolved_user.role not in roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access forbidden: requires one of the roles {roles}",
                )
            return resolved_user
        return dependency

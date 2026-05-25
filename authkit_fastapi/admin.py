import os
import uuid
from typing import Optional, Any
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from authkit_fastapi.router import set_auth_cookies, clear_auth_cookies

# Request bodies for JSON actions
class ToggleActiveRequest(BaseModel):
    is_active: bool

class ChangeRoleRequest(BaseModel):
    role: str

def get_admin_router(auth_kit) -> APIRouter:
    """Build and return the visual Jinja2 admin interface router."""
    router = APIRouter()
    config = auth_kit.config
    auth_service = auth_kit.auth_service
    get_db = auth_kit.get_db
    
    # Path resolution for internal Jinja2 templates
    current_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(current_dir, "templates")
    templates = Jinja2Templates(directory=templates_dir)

    async def get_admin_user(request: Request, db: AsyncSession) -> Optional[Any]:
        """Verify request belongs to an authenticated administrator."""
        token = request.cookies.get(config.cookie_name_access)
        if not token:
            # Fallback to Authorization header if cookie not present
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                token = auth_header[7:]
                
        if not token:
            return None
            
        payload = auth_service.decode_token(token)
        if not payload or payload.get("type") != "access":
            return None
            
        if payload.get("role") != config.admin_role:
            return None
            
        user_id = payload.get("sub")
        
        # Verify that the session is active and not revoked in the database
        refresh_token = request.cookies.get(config.cookie_name_refresh)
        if refresh_token:
            refresh_payload = auth_service.decode_token(refresh_token)
            if refresh_payload:
                jti = refresh_payload.get("jti")
                if jti:
                    stmt = select(auth_kit.refresh_token_model).where(
                        auth_kit.refresh_token_model.jti == jti
                    )
                    res = await db.execute(stmt)
                    session = res.scalar_one_or_none()
                    if not session or session.is_revoked:
                        return None

        stmt = select(auth_kit.user_model).where(auth_kit.user_model.id == user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user or not user.is_active:
            return None
            
        return user

    @router.get("/", response_class=HTMLResponse)
    async def admin_root(request: Request, db: AsyncSession = Depends(get_db)):
        """Redirect admin root to dashboard or login."""
        admin = await get_admin_user(request, db)
        if not admin:
            response = RedirectResponse(url=f"{config.admin_path}/login", status_code=status.HTTP_303_SEE_OTHER)
            clear_auth_cookies(response, config)
            return response
        return RedirectResponse(url=f"{config.admin_path}/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @router.get("/login", response_class=HTMLResponse)
    async def get_login(request: Request, db: AsyncSession = Depends(get_db)):
        """Render the admin login panel."""
        admin = await get_admin_user(request, db)
        if admin:
            return RedirectResponse(url=f"{config.admin_path}/dashboard", status_code=status.HTTP_303_SEE_OTHER)
            
        return templates.TemplateResponse(
            request=request,
            name="login.html", 
            context={"admin_path": config.admin_path, "show_nav": False}
        )

    @router.post("/login", response_class=HTMLResponse)
    async def post_login(
        request: Request,
        response: Response,
        email: str = Form(...),
        password: str = Form(...),
        db: AsyncSession = Depends(get_db)
    ):
        """Handle admin panel login via HTML Form submission."""
        # 1. Authenticate user
        stmt = select(auth_kit.user_model).where(auth_kit.user_model.email == email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user or not auth_service.verify_password(password, user.hashed_password):
            await auth_kit.log_action(
                db=db,
                action="failed_admin_login",
                details={"email": email},
                request=request
            )
            return templates.TemplateResponse(
                request=request,
                name="login.html", 
                context={"admin_path": config.admin_path, "show_nav": False, "error": "Incorrect email or password.", "email": email}
            )
            
        if user.role != config.admin_role:
            await auth_kit.log_action(
                db=db,
                user_id=user.id,
                action="unauthorized_admin_login_attempt",
                request=request
            )
            return templates.TemplateResponse(
                request=request,
                name="login.html", 
                context={"admin_path": config.admin_path, "show_nav": False, "error": "Access forbidden: administrator credentials required.", "email": email}
            )
            
        if not user.is_active:
            return templates.TemplateResponse(
                request=request,
                name="login.html", 
                context={"admin_path": config.admin_path, "show_nav": False, "error": "Account is deactivated.", "email": email}
            )

        # 2. Issue tokens
        jti = str(uuid.uuid4())
        access_token = auth_service.create_access_token(user.id, user.role)
        refresh_token = auth_service.create_refresh_token(user.id, jti)
        
        # 3. Create session record
        ip_addr = None
        if request.client:
            ip_addr = request.client.host
        x_forwarded_for = request.headers.get("x-forwarded-for")
        if x_forwarded_for:
            ip_addr = x_forwarded_for.split(",")[0].strip()
            
        user_agent = request.headers.get("user-agent")
        
        await auth_service.create_session(
            db=db,
            user_id=user.id,
            jti=jti,
            token=refresh_token,
            ip_address=ip_addr,
            user_agent=user_agent
        )
        
        # Log successful admin login
        await auth_kit.log_action(
            db=db,
            user_id=user.id,
            action="admin_logged_in",
            request=request
        )

        # 4. Redirect with cookies
        redir_response = RedirectResponse(url=f"{config.admin_path}/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        set_auth_cookies(redir_response, config, access_token, refresh_token)
        return redir_response

    @router.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
        """Render user base, session management table, and stats."""
        admin = await get_admin_user(request, db)
        if not admin:
            response = RedirectResponse(url=f"{config.admin_path}/login", status_code=status.HTTP_303_SEE_OTHER)
            clear_auth_cookies(response, config)
            return response
            
        # 1. Fetch metrics
        total_stmt = select(func.count(auth_kit.user_model.id))
        active_stmt = select(func.count(auth_kit.user_model.id)).where(auth_kit.user_model.is_active == True)
        sessions_stmt = select(func.count(auth_kit.refresh_token_model.id)).where(auth_kit.refresh_token_model.is_revoked == False)
        
        total_users = (await db.execute(total_stmt)).scalar() or 0
        active_users = (await db.execute(active_stmt)).scalar() or 0
        active_sessions = (await db.execute(sessions_stmt)).scalar() or 0
        
        stats = {
            "total_users": total_users,
            "active_users": active_users,
            "active_sessions": active_sessions
        }
        
        # 2. Fetch users
        users_stmt = select(auth_kit.user_model).order_by(auth_kit.user_model.created_at.desc())
        users = (await db.execute(users_stmt)).scalars().all()
        
        # 3. Fetch active sessions (with eager loading of User relation)
        sessions_stmt = select(
            auth_kit.refresh_token_model
        ).options(
            selectinload(auth_kit.refresh_token_model.user)
        ).where(
            auth_kit.refresh_token_model.is_revoked == False
        ).order_by(
            auth_kit.refresh_token_model.created_at.desc()
        )
        sessions = (await db.execute(sessions_stmt)).scalars().all()
        
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "admin_path": config.admin_path,
                "active_page": "dashboard",
                "stats": stats,
                "users": users,
                "sessions": sessions,
                "show_nav": True
            }
        )

    @router.get("/audit-logs", response_class=HTMLResponse)
    async def get_audit_logs(request: Request, db: AsyncSession = Depends(get_db)):
        """Render system audit trails list."""
        admin = await get_admin_user(request, db)
        if not admin:
            response = RedirectResponse(url=f"{config.admin_path}/login", status_code=status.HTTP_303_SEE_OTHER)
            clear_auth_cookies(response, config)
            return response
            
        # Fetch audit logs with eager loading of User relation
        stmt = select(
            auth_kit.audit_log_model
        ).options(
            selectinload(auth_kit.audit_log_model.user)
        ).order_by(
            auth_kit.audit_log_model.created_at.desc()
        )
        logs = (await db.execute(stmt)).scalars().all()
        
        return templates.TemplateResponse(
            request=request,
            name="audit_logs.html",
            context={
                "admin_path": config.admin_path,
                "active_page": "audit_logs",
                "logs": logs,
                "show_nav": True
            }
        )

    @router.get("/reset-password", response_class=HTMLResponse)
    async def get_reset_password(request: Request, token: str):
        """Render password set screen from forgot password link."""
        return templates.TemplateResponse(
            request=request,
            name="reset_password.html",
            context={
                "token": token,
                "admin_path": config.admin_path,
                "show_nav": False
            }
        )

    # AJAX Actions

    @router.post("/users/{user_id}/toggle-active")
    async def toggle_active(
        user_id: str,
        body: ToggleActiveRequest,
        request: Request,
        db: AsyncSession = Depends(get_db)
    ):
        """AJAX handler to activate or deactivate a user account."""
        admin = await get_admin_user(request, db)
        if not admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
            
        stmt = select(auth_kit.user_model).where(auth_kit.user_model.id == user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        if user.id == admin.id:
            raise HTTPException(status_code=400, detail="Cannot deactivate yourself")
            
        user.is_active = body.is_active
        
        # If deactivating, revoke all their active sessions
        if not body.is_active:
            await auth_service.revoke_all_sessions(db, user.id)
            
        await db.commit()
        
        await auth_kit.log_action(
            db=db,
            user_id=admin.id,
            action="admin_toggled_user_active",
            details={"target_user_id": user_id, "is_active": body.is_active},
            request=request
        )
        return {"success": True}

    @router.post("/users/{user_id}/change-role")
    async def change_role(
        user_id: str,
        body: ChangeRoleRequest,
        request: Request,
        db: AsyncSession = Depends(get_db)
    ):
        """AJAX handler to alter a user's role."""
        admin = await get_admin_user(request, db)
        if not admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
            
        stmt = select(auth_kit.user_model).where(auth_kit.user_model.id == user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        if user.id == admin.id:
            raise HTTPException(status_code=400, detail="Cannot demote yourself from admin")
            
        old_role = user.role
        user.role = body.role
        await db.commit()
        
        await auth_kit.log_action(
            db=db,
            user_id=admin.id,
            action="admin_changed_user_role",
            details={"target_user_id": user_id, "old_role": old_role, "new_role": body.role},
            request=request
        )
        return {"success": True}

    @router.post("/users/{user_id}/delete")
    async def delete_user(
        user_id: str,
        request: Request,
        db: AsyncSession = Depends(get_db)
    ):
        """AJAX handler to purge a user account from database."""
        admin = await get_admin_user(request, db)
        if not admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
            
        stmt = select(auth_kit.user_model).where(auth_kit.user_model.id == user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        if user.id == admin.id:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")
            
        # Due to CASCADE constraint, deleting the user cascades deletions to refresh tokens and sets user_id null on audit logs
        email = user.email
        await db.delete(user)
        await db.commit()
        
        await auth_kit.log_action(
            db=db,
            user_id=admin.id,
            action="admin_deleted_user",
            details={"target_user_id": user_id, "email": email},
            request=request
        )
        return {"success": True}

    @router.post("/sessions/{session_id}/revoke")
    async def revoke_user_session(
        session_id: str,
        request: Request,
        db: AsyncSession = Depends(get_db)
    ):
        """AJAX handler to force-terminate an active user session."""
        admin = await get_admin_user(request, db)
        if not admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
            
        stmt = select(auth_kit.refresh_token_model).where(auth_kit.refresh_token_model.id == session_id)
        result = await db.execute(stmt)
        session = result.scalar_one_or_none()
        
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
            
        # Safety constraint: Prevent admins from revoking their own current active session
        refresh_token = request.cookies.get(config.cookie_name_refresh)
        if not refresh_token:
            # check authorization header fallback
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                refresh_token = auth_header[7:]
                
        if refresh_token:
            payload = auth_service.decode_token(refresh_token)
            if payload and payload.get("jti") == session.jti:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, 
                    detail="Cannot revoke your own active session. Please use the Logout button instead."
                )
            
        session.is_revoked = True
        await db.commit()
        
        await auth_kit.log_action(
            db=db,
            user_id=admin.id,
            action="admin_revoked_session",
            details={"revoked_session_id": session_id, "target_user_id": session.user_id},
            request=request
        )
        return {"success": True}

    return router

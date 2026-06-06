import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authkit_fastapi.schemas import (
    UserCreate,
    UserRead,
    TokenResponse,
    LoginRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
)

def set_auth_cookies(response: Response, config, access_token: str, refresh_token: str):
    """Set HTTP-only cookies for access and refresh tokens."""
    response.set_cookie(
        key=config.cookie_name_access,
        value=access_token,
        httponly=True,
        secure=config.cookie_secure,
        samesite=config.cookie_samesite,
        domain=config.cookie_domain,
        max_age=config.access_token_expire_minutes * 60,
    )
    response.set_cookie(
        key=config.cookie_name_refresh,
        value=refresh_token,
        httponly=True,
        secure=config.cookie_secure,
        samesite=config.cookie_samesite,
        domain=config.cookie_domain,
        max_age=config.refresh_token_expire_days * 24 * 60 * 60,
    )

def clear_auth_cookies(response: Response, config):
    """Delete HTTP-only cookies on logout."""
    response.delete_cookie(
        key=config.cookie_name_access,
        domain=config.cookie_domain,
        samesite=config.cookie_samesite,
    )
    response.delete_cookie(
        key=config.cookie_name_refresh,
        domain=config.cookie_domain,
        samesite=config.cookie_samesite,
    )

def get_auth_router(auth_kit) -> APIRouter:
    """Build and return the core authentication API router."""
    router = APIRouter()
    config = auth_kit.config
    auth_service = auth_kit.auth_service
    email_service = auth_kit.email_service
    get_db = auth_kit.get_db

    @router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
    async def register(
        user_data: UserCreate, 
        request: Request,
        db: AsyncSession = Depends(get_db)
    ):
        """Register a new user account."""
        if not config.enable_register:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Registration is currently disabled."
            )
            
        # Check if email is already taken
        stmt = select(auth_kit.user_model).where(auth_kit.user_model.email == user_data.email)
        result = await db.execute(stmt)
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already registered."
            )
            
        # Create new user
        hashed_pw = auth_service.hash_password(user_data.password)
        new_user = auth_kit.user_model(
            email=user_data.email,
            hashed_password=hashed_pw,
            role="user",
            is_active=True,
            is_verified=False
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        
        # Log audit action
        await auth_kit.log_action(
            db=db,
            user_id=new_user.id,
            action="user_registered",
            details={"email": new_user.email},
            request=request
        )
        
        return new_user

    @router.post("/login", response_model=TokenResponse)
    async def login(
        login_data: LoginRequest,
        response: Response,
        request: Request,
        db: AsyncSession = Depends(get_db)
    ):
        """Authenticate user and return access/refresh tokens via body and HTTP-only cookies."""
        stmt = select(auth_kit.user_model).where(auth_kit.user_model.email == login_data.email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user or not auth_service.verify_password(login_data.password, user.hashed_password):
            # Log failed attempt
            await auth_kit.log_action(
                db=db,
                action="failed_login_attempt",
                details={"email": login_data.email},
                request=request
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password."
            )
            
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated."
            )
            
        # Generate tokens
        jti = str(uuid.uuid4())
        access_token = auth_service.create_access_token(user)
        refresh_token = auth_service.create_refresh_token(user.id, jti)
        
        # Save session to DB
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
        
        # Set cookies
        set_auth_cookies(response, config, access_token, refresh_token)
        
        # Log audit action
        await auth_kit.log_action(
            db=db,
            user_id=user.id,
            action="user_logged_in",
            request=request
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }

    @router.post("/refresh", response_model=TokenResponse)
    async def refresh(
        response: Response,
        request: Request,
        db: AsyncSession = Depends(get_db)
    ):
        """Rotate access and refresh tokens, validating active sessions in the database."""
        # 1. Read refresh token from cookie or authorization header
        refresh_token = request.cookies.get(config.cookie_name_refresh)
        if not refresh_token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                refresh_token = auth_header[7:]
                
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token missing."
            )
            
        # 2. Decode refresh token
        payload = auth_service.decode_token(refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token."
            )
            
        user_id_str = payload.get("sub")
        jti = payload.get("jti")
        
        # 3. Verify session in DB
        session = await auth_service.verify_session(db, jti, refresh_token)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session revoked or invalid."
            )
            
        try:
            uuid_user_id = uuid.UUID(user_id_str)
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token."
            )

        # 4. Fetch user
        stmt = select(auth_kit.user_model).where(auth_kit.user_model.id == uuid_user_id)
        res = await db.execute(stmt)
        user = res.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User inactive or not found."
            )
            
        # 5. Revoke old session and issue new tokens (rotation)
        await auth_service.revoke_session(db, jti)
        
        new_jti = str(uuid.uuid4())
        new_access = auth_service.create_access_token(user)
        new_refresh = auth_service.create_refresh_token(user.id, new_jti)
        
        # Save new session
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
            jti=new_jti,
            token=new_refresh,
            ip_address=ip_addr,
            user_agent=user_agent
        )
        
        # Set cookies
        set_auth_cookies(response, config, new_access, new_refresh)
        
        return {
            "access_token": new_access,
            "refresh_token": new_refresh,
            "token_type": "bearer"
        }

    @router.post("/logout")
    async def logout(
        response: Response,
        request: Request,
        db: AsyncSession = Depends(get_db)
    ):
        """Revoke current session and clear auth cookies."""
        # Get refresh token to identify the session
        refresh_token = request.cookies.get(config.cookie_name_refresh)
        if not refresh_token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                refresh_token = auth_header[7:]
                
        user_id = None
        if refresh_token:
            payload = auth_service.decode_token(refresh_token)
            if payload:
                jti = payload.get("jti")
                user_id = payload.get("sub")
                if jti:
                    await auth_service.revoke_session(db, jti)
                    
        # Clear cookies
        clear_auth_cookies(response, config)
        
        # Log audit action
        if user_id:
            await auth_kit.log_action(
                db=db,
                user_id=user_id,
                action="user_logged_out",
                request=request
            )
            
        return {"message": "Successfully logged out."}

    @router.post("/logout-all")
    async def logout_all(
        response: Response,
        request: Request,
        current_user = Depends(auth_kit.current_active_user),
        db: AsyncSession = Depends(get_db)
    ):
        """Revoke all sessions for the current authenticated user across all devices."""
        await auth_service.revoke_all_sessions(db, current_user.id)
        clear_auth_cookies(response, config)
        
        # Log audit action
        await auth_kit.log_action(
            db=db,
            user_id=current_user.id,
            action="user_logged_out_all_devices",
            request=request
        )
        
        return {"message": "Successfully logged out of all devices."}

    @router.post("/forgot-password")
    async def forgot_password(
        data: ForgotPasswordRequest,
        request: Request,
        db: AsyncSession = Depends(get_db)
    ):
        """Send a password reset email if the account exists."""
        stmt = select(auth_kit.user_model).where(auth_kit.user_model.email == data.email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if user and user.is_active:
            reset_token = auth_service.create_reset_token(user.id, user.hashed_password)
            
            # Formulate verification links
            base_url = str(request.base_url).rstrip("/")
            reset_link = f"{base_url}/admin/reset-password?token={reset_token}"
            
            subject = "Password Reset Request"
            body_text = f"Hello,\n\nYou requested a password reset. Please click the link below to set a new password:\n\n{reset_link}\n\nThis link is valid for 15 minutes.\nIf you did not request this, please ignore this email."
            body_html = f"""
            <div style="font-family: sans-serif; padding: 20px; color: #333;">
                <h2>Password Reset Request</h2>
                <p>Hello,</p>
                <p>You requested a password reset. Click the button below to set a new password:</p>
                <p style="margin: 30px 0;">
                    <a href="{reset_link}" style="background-color: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">Reset Password</a>
                </p>
                <p>Or copy and paste this link into your browser:</p>
                <p><a href="{reset_link}">{reset_link}</a></p>
                <p><em>This link is valid for 15 minutes.</em></p>
                <hr style="border: 0; border-top: 1px solid #eee; margin-top: 30px;">
                <p style="font-size: 12px; color: #777;">If you did not make this request, you can safely ignore this email.</p>
            </div>
            """
            
            await email_service.send_email(user.email, subject, body_text, body_html)
            
            # Log audit
            await auth_kit.log_action(
                db=db,
                user_id=user.id,
                action="password_reset_requested",
                request=request
            )
            
        # Return generic success response to prevent email harvesting enumeration attacks
        return {"message": "If the email is registered, a password reset link has been sent."}

    @router.post("/reset-password")
    async def reset_password(
        data: ResetPasswordRequest,
        request: Request,
        db: AsyncSession = Depends(get_db)
    ):
        """Set a new password using a valid reset-password token."""
        payload = auth_service.decode_token(data.token)
        if not payload or payload.get("action") != "reset_password":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token."
            )
            
        user_id_str = payload.get("sub")
        try:
            uuid_user_id = uuid.UUID(user_id_str)
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token."
            )
        stmt = select(auth_kit.user_model).where(auth_kit.user_model.id == uuid_user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not found or deactivated."
            )
            
        import hashlib
        current_pwd_sec = hashlib.sha256(user.hashed_password.encode()).hexdigest()[:16]
        if payload.get("pwd_sec") != current_pwd_sec:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This reset token has already been used or is invalid."
            )
            
        # Update password
        user.hashed_password = auth_service.hash_password(data.new_password)
        
        # Revoke all sessions (forces re-login on all devices for security)
        await auth_service.revoke_all_sessions(db, user.id)
        
        await db.commit()
        
        # Log audit
        await auth_kit.log_action(
            db=db,
            user_id=user.id,
            action="password_reset_completed",
            request=request
        )
        
        return {"message": "Password successfully reset. Active sessions have been logged out."}

    @router.get("/me", response_model=UserRead)
    async def get_me(current_user = Depends(auth_kit.current_active_user)):
        """Fetch the current authenticated user profile."""
        return current_user

    return router

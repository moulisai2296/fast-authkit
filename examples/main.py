import uvicorn
from fastapi import FastAPI, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

# Import our plugin assets
from authkit_fastapi import AuthKit, AuthKitConfig
from authkit_fastapi.models import User, RefreshToken, AuditLog
from examples.mock_db import async_session, init_and_seed_db

# 1. Configuration
# We disable cookie_secure for local development (http://localhost)
config = AuthKitConfig(
    secret_key="sandbox-secret-key-make-it-long-and-secure",
    cookie_secure=False,
    cookie_samesite="lax",
    enable_register=True,
    enable_audit_logs=True
)

# 2. Instantiate AuthKit with our SQLite sandbox database session maker
auth_kit = AuthKit(
    config=config,
    db_session_maker=async_session,
    user_model=User,
    refresh_token_model=RefreshToken,
    audit_log_model=AuditLog
)

# 3. Create FastAPI App
app = FastAPI(
    title="AuthKit Sandbox",
    description="Interactive local environment for testing AuthKit auth flows and admin dashboards.",
    version="1.0.0"
)

# 4. Mount AuthKit Routers
# Mounting core auth APIs (register, login, refresh, logout, profile)
app.include_router(auth_kit.router, prefix="/auth", tags=["Authentication"])
# Mounting visual HTML Admin interface (dashboard, audit logs, sessions)
app.include_router(auth_kit.admin_router, prefix="/admin", tags=["Admin Dashboard"])

# 5. Define Startup Seeding Hook
@app.on_event("startup")
async def startup():
    await init_and_seed_db()

# 6. Set up Custom Secured Routes to test local extension capabilities

@app.get("/secure-data")
async def secure_endpoint(
    current_user = Depends(auth_kit.current_active_user)
):
    """A standard protected endpoint accessible by any active logged-in user."""
    return {
        "message": "This is highly secure data from the host application.",
        "user": {
            "email": current_user.email,
            "role": current_user.role,
            "id": current_user.id
        }
    }

@app.get("/admin-only")
async def admin_only_endpoint(
    current_user = Depends(auth_kit.current_admin)
):
    """A protected endpoint restricted strictly to administrators."""
    return {
        "message": "Welcome back, master admin! Access granted.",
        "admin_id": current_user.id
    }

@app.post("/custom-audit")
async def custom_audit_endpoint(
    request: Request,
    db: AsyncSession = Depends(auth_kit.get_db),
    current_user = Depends(auth_kit.current_active_user)
):
    """An endpoint demonstrating hybrid manual audit logging by the host app."""
    # Run some custom task...
    payload_processed = {"item": "Quantum AI Model", "action": "train_model", "epochs": 50}
    
    # Write custom log entry manually
    await auth_kit.log_action(
        db=db,
        action="trained_ai_model",
        user_id=current_user.id,
        details=payload_processed,
        request=request
    )
    
    return {
        "success": True,
        "message": "Custom action performed and successfully audited in database."
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

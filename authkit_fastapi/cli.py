import os
import sys
import argparse
import secrets

MODELS_TEMPLATE = """import uuid
from typing import Optional
from sqlalchemy import Uuid, ForeignKey, mapped_column
from sqlalchemy.orm import Mapped, relationship
from authkit_fastapi.models import Base, BaseUserMixin, BaseRefreshTokenMixin, BaseAuditLogMixin

# =========================================================================
# Customize Your Database Schema Here
# You can add custom columns, constraints, or relationships.
# After changes, generate migration script with Alembic.
# =========================================================================

class User(Base, BaseUserMixin):
    __tablename__ = "users"
    
    # Custom fields can go here (e.g. name = mapped_column(String(100)))
    
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken", 
        back_populates="user", 
        cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog", 
        back_populates="user", 
        cascade="all, delete-orphan"
    )

class RefreshToken(Base, BaseRefreshTokenMixin):
    __tablename__ = "refresh_tokens"
    
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, 
        ForeignKey("users.id", ondelete="CASCADE"), 
        index=True, 
        nullable=False
    )
    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")

class AuditLog(Base, BaseAuditLogMixin):
    __tablename__ = "audit_logs"
    
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, 
        ForeignKey("users.id", ondelete="SET NULL"), 
        index=True, 
        nullable=True
    )
    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")
"""

SCHEMAS_TEMPLATE = """from typing import Optional
from authkit_fastapi.schemas import UserCreate, UserRead, UserUpdate

# =========================================================================
# Customize Your Pydantic Validation Schemas Here
# Extend these models to match any custom columns added to your models.py.
# =========================================================================

class CustomUserCreate(UserCreate):
    # Add custom validation fields (e.g., name: str)
    pass

class CustomUserRead(UserRead):
    # Expose custom fields in api responses
    pass

class CustomUserUpdate(UserUpdate):
    pass
"""

SETUP_TEMPLATE = """import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from authkit_fastapi import AuthKit, AuthKitConfig
from .models import Base, User, RefreshToken, AuditLog

# 1. Load config from environment or local .env file
config = AuthKitConfig()

# 2. Setup Database Async Connection
DATABASE_URL = os.getenv("AUTHKIT_DATABASE_URL", "sqlite+aiosqlite:///./authkit.db")

connect_args = {}
# SQLite async parameters
if "sqlite" in DATABASE_URL:
    connect_args["check_same_thread"] = False

engine = create_async_engine(
    DATABASE_URL,
    connect_args=connect_args,
    future=True
)
async_session = async_sessionmaker(engine, expire_on_commit=False)

# 3. Instantiate AuthKit Engine
auth_kit = AuthKit(
    config=config,
    db_session_maker=async_session,
    user_model=User,
    refresh_token_model=RefreshToken,
    audit_log_model=AuditLog
)

# 4. Helper to initialize database tables (useful for sandbox development)
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
"""

INIT_TEMPLATE = """from .setup import auth_kit, init_db
"""

ENV_TEMPLATE = """# AuthKit Security Configuration
AUTHKIT_SECRET_KEY={secret_key}
AUTHKIT_DATABASE_URL=sqlite+aiosqlite:///./authkit.db

# Cookie Settings
AUTHKIT_COOKIE_SECURE=False
AUTHKIT_COOKIE_SAMESITE=lax

# Email Settings (Fill these to enable password reset SMTP)
AUTHKIT_ENABLE_SMTP=False
# AUTHKIT_SMTP_HOST=smtp.gmail.com
# AUTHKIT_SMTP_PORT=587
# AUTHKIT_SMTP_USERNAME=your-email@gmail.com
# AUTHKIT_SMTP_PASSWORD=your-app-password
# AUTHKIT_SMTP_FROM_EMAIL=no-reply@authkit.local
"""

ENV_EXAMPLE_TEMPLATE = """# AuthKit Security Configuration
AUTHKIT_SECRET_KEY=
AUTHKIT_DATABASE_URL=sqlite+aiosqlite:///./authkit.db

# Cookie Settings
AUTHKIT_COOKIE_SECURE=False
AUTHKIT_COOKIE_SAMESITE=lax

# Email Settings
AUTHKIT_ENABLE_SMTP=False
# AUTHKIT_SMTP_HOST=
# AUTHKIT_SMTP_PORT=587
# AUTHKIT_SMTP_USERNAME=
# AUTHKIT_SMTP_PASSWORD=
# AUTHKIT_SMTP_FROM_EMAIL=
"""

def main():
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="AuthKit FastAPI Plugin Command-Line Tool")
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # init command
    init_parser = subparsers.add_parser("init", help="Bootstrap AuthKit module and environment configuration in current project")

    args = parser.parse_args()

    if args.command == "init":
        bootstrap_project()
    else:
        parser.print_help()

def bootstrap_project():
    print("🚀 Initializing AuthKit in local project workspace...")
    
    # 1. Create auth/ directory
    auth_dir = "auth"
    if not os.path.exists(auth_dir):
        os.makedirs(auth_dir)
        print(f"  [Created] Directory: ./{auth_dir}")
    else:
        print(f"  [Info] Directory ./{auth_dir} already exists. Skipping directory creation.")

    # 2. Write file structures
    files_to_write = {
        os.path.join(auth_dir, "__init__.py"): INIT_TEMPLATE,
        os.path.join(auth_dir, "models.py"): MODELS_TEMPLATE,
        os.path.join(auth_dir, "schemas.py"): SCHEMAS_TEMPLATE,
        os.path.join(auth_dir, "setup.py"): SETUP_TEMPLATE,
        ".env.example": ENV_EXAMPLE_TEMPLATE,
    }

    # Only write .env if it does not already exist, generating a strong random secret
    if not os.path.exists(".env"):
        random_secret = secrets.token_hex(32)
        files_to_write[".env"] = ENV_TEMPLATE.format(secret_key=random_secret)

    for path, content in files_to_write.items():
        if os.path.exists(path):
            print(f"  [Skip] File {path} already exists. Skipping writing to avoid overwriting changes.")
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [Created] File: {path}")

    print("\n🎉 AuthKit successfully scaffolded!")
    print("\nNext Steps:")
    print("1. Set your environment variables in the newly created `.env` file.")
    print("2. Import and mount AuthKit in your main FastAPI application (e.g. `main.py`):")
    print("   ```python")
    print("   from fastapi import FastAPI")
    print("   from auth import auth_kit, init_db")
    print("   ")
    print("   app = FastAPI()")
    print("   ")
    print("   # Mount Routers")
    print("   app.include_router(auth_kit.router, prefix=\"/auth\", tags=[\"Authentication\"])")
    print("   app.include_router(auth_kit.admin_router, prefix=\"/admin\", tags=[\"Admin\"])")
    print("   ")
    print("   @app.on_event(\"startup\")")
    print("   async def startup():")
    print("       await init_db()")
    print("   ```")
    print("3. Spin up your server with `uvicorn main:app --reload` and go to http://127.0.0.1:8000/admin")

if __name__ == "__main__":
    main()

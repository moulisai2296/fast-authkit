import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select
from authkit_fastapi.models import Base, User, RefreshToken, AuditLog
from authkit_fastapi.auth_service import AuthService
from authkit_fastapi.config import AuthKitConfig

DATABASE_URL = "sqlite+aiosqlite:///./sandbox.db"

engine = create_async_engine(DATABASE_URL, connect_args={"check_same_thread": False})
async_session = async_sessionmaker(engine, expire_on_commit=False)

async def init_and_seed_db():
    """Seed sandbox database with mock accounts if not already initialized."""
    # We do NOT remove sandbox.db so records persist across code changes/restarts!
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as db:
        # Check if users already exist to avoid duplicate seeding
        stmt = select(User).where(User.email == "admin@example.com")
        result = await db.execute(stmt)
        if not result.scalar_one_or_none():
            config = AuthKitConfig()
            auth_service = AuthService(config, User, RefreshToken, AuditLog)
            
            # 1. Admin
            admin = User(
                email="admin@example.com",
                hashed_password=auth_service.hash_password("adminpass123"),
                role="admin",
                is_active=True,
                is_verified=True
            )
            db.add(admin)
            
            # 2. Normal User
            user = User(
                email="user@example.com",
                hashed_password=auth_service.hash_password("userpass123"),
                role="user",
                is_active=True,
                is_verified=True
            )
            db.add(user)
            
            # 3. Deactivated User
            deactivated = User(
                email="deactivated@example.com",
                hashed_password=auth_service.hash_password("deactivated123"),
                role="user",
                is_active=False,
                is_verified=True
            )
            db.add(deactivated)
            
            await db.commit()
            print("------------------------------------------------------------------------")
            print("Database successfully seeded:")
            print("  - Admin User: admin@example.com (Password: adminpass123)")
            print("  - Normal User: user@example.com (Password: userpass123)")
            print("  - Banned User: deactivated@example.com (Password: deactivated123)")
            print("------------------------------------------------------------------------")
        else:
            print(" Sandbox database already exists. Skipping seeding to preserve data.")

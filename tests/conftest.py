import asyncio
import uuid
import pytest
import pytest_asyncio
from typing import AsyncGenerator
from fastapi import FastAPI, Depends
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import StaticPool

from authkit_fastapi import AuthKit, AuthKitConfig
from authkit_fastapi.models import Base
from authkit_fastapi.models_concrete import User, RefreshToken, AuditLog, BaseConcrete

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()

@pytest_asyncio.fixture(scope="function")
async def test_engine():
    """Create an in-memory SQLite engine for unit tests."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(BaseConcrete.metadata.create_all)
    yield engine
    await engine.dispose()

@pytest_asyncio.fixture(scope="function")
async def test_session_maker(test_engine):
    """Create an async session maker tied to the test engine."""
    return async_sessionmaker(test_engine, expire_on_commit=False)

@pytest_asyncio.fixture(scope="function")
async def db(test_session_maker) -> AsyncGenerator[AsyncSession, None]:
    """Yield a database session and roll back changes after test execution."""
    async with test_session_maker() as session:
        yield session

@pytest.fixture(scope="function")
def auth_kit_config():
    """Return standard configurations for testing."""
    return AuthKitConfig(
        secret_key="test-secret-key-make-it-long-and-secure",
        cookie_secure=False,
        cookie_samesite="lax",
        enable_register=True,
        enable_audit_logs=True
    )

@pytest.fixture(scope="function")
def auth_kit(auth_kit_config, test_session_maker):
    """Return an AuthKit instance configured for testing."""
    return AuthKit(
        config=auth_kit_config,
        db_session_maker=test_session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        audit_log_model=AuditLog
    )

@pytest.fixture(scope="function")
def test_app(auth_kit) -> FastAPI:
    """FastAPI test app instance mounting the routers."""
    app = FastAPI()
    app.include_router(auth_kit.router, prefix="/auth")
    app.include_router(auth_kit.admin_router, prefix="/admin")
    
    # Custom secure route
    @app.get("/secure")
    def secure_route(user=Depends(auth_kit.current_active_user)):
        return {"user_id": user.id, "email": user.email}
        
    return app

@pytest_asyncio.fixture(scope="function")
async def client(test_app) -> AsyncGenerator[AsyncClient, None]:
    """Yield an HTTPX AsyncClient bound to the test app."""
    # We use transport in HTTPX 0.20+
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

@pytest_asyncio.fixture(scope="function")
async def seed_users(db, auth_kit):
    """Seed test users into database: admin and regular user."""
    auth_service = auth_kit.auth_service
    
    # Hash password
    admin_pw = auth_service.hash_password("adminpass")
    user_pw = auth_service.hash_password("userpass")
    
    admin = User(
        id=uuid.UUID("11111111-1111-4111-a111-111111111111"),
        email="admin@test.com",
        hashed_password=admin_pw,
        role="admin",
        is_active=True,
        is_verified=True
    )
    user = User(
        id=uuid.UUID("22222222-2222-4222-a222-222222222222"),
        email="user@test.com",
        hashed_password=user_pw,
        role="user",
        is_active=True,
        is_verified=True
    )
    deactivated = User(
        id=uuid.UUID("33333333-3333-4333-a333-333333333333"),
        email="deactivated@test.com",
        hashed_password=user_pw,
        role="user",
        is_active=False,
        is_verified=True
    )
    
    db.add_all([admin, user, deactivated])
    await db.commit()
    return {"admin": admin, "user": user, "deactivated": deactivated}

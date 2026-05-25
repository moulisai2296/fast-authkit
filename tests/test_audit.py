import pytest
from sqlalchemy import select
from authkit_fastapi import AuthKit, AuthKitConfig
from authkit_fastapi.models import User, RefreshToken, AuditLog

@pytest.mark.asyncio
async def test_automatic_register_audit_log(client, db):
    # Register user
    await client.post("/auth/register", json={
        "email": "auditeduser@test.com",
        "password": "StrongPass123!"
    })
    
    # Check Audit Log in DB
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
    result = await db.execute(stmt)
    logs = result.scalars().all()
    
    # Must have logged "user_registered"
    assert len(logs) == 1
    assert logs[0].action == "user_registered"
    assert logs[0].details["email"] == "auditeduser@test.com"

@pytest.mark.asyncio
async def test_automatic_failed_login_audit_log(client, seed_users, db):
    # Try invalid login
    await client.post("/auth/login", json={
        "email": "user@test.com",
        "password": "wrongpassword"
    })
    
    # Check DB
    stmt = select(AuditLog).where(AuditLog.action == "failed_login_attempt")
    result = await db.execute(stmt)
    log = result.scalar_one_or_none()
    assert log is not None
    assert log.details["email"] == "user@test.com"

@pytest.mark.asyncio
async def test_manual_log_action(auth_kit, seed_users, db):
    # Log custom action manually
    log = await auth_kit.log_action(
        db=db,
        action="processed_payment",
        user_id="user-uuid-222",
        details={"amount": 99.99, "currency": "USD"}
    )
    assert log is not None
    assert log.action == "processed_payment"
    assert log.details["amount"] == 99.99
    
    # Check DB persists it
    stmt = select(AuditLog).where(AuditLog.id == log.id)
    persisted = (await db.execute(stmt)).scalar_one_or_none()
    assert persisted is not None
    assert persisted.user_id == "user-uuid-222"

@pytest.mark.asyncio
async def test_audit_logs_disabled_toggle(auth_kit_config, test_session_maker, db):
    # Disable audit logs in config
    disabled_config = AuthKitConfig(
        secret_key="secret",
        enable_audit_logs=False
    )
    disabled_authkit = AuthKit(
        config=disabled_config,
        db_session_maker=test_session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        audit_log_model=AuditLog
    )
    
    # Try logging action
    log = await disabled_authkit.log_action(
        db=db,
        action="some_action",
        user_id="user-uuid-222"
    )
    # Service should return None since logs are disabled
    assert log is None
    
    # Check DB remains empty
    stmt = select(AuditLog)
    result = await db.execute(stmt)
    assert len(result.scalars().all()) == 0

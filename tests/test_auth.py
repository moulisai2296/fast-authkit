import pytest
from sqlalchemy import select
from authkit_fastapi.models import User, RefreshToken, AuditLog

@pytest.mark.asyncio
async def test_register_success(client, db):
    response = await client.post("/auth/register", json={
        "email": "newuser@test.com",
        "password": "StrongPass123!"
    })
    assert response.status_code == 210 or response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@test.com"
    assert "id" in data
    
    # Verify user exists in database
    stmt = select(User).where(User.email == "newuser@test.com")
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    assert user is not None
    assert user.role == "user"

@pytest.mark.asyncio
async def test_register_duplicate_email(client, seed_users):
    response = await client.post("/auth/register", json={
        "email": "user@test.com", # already exists in seed_users
        "password": "StrongPass123!"
    })
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"]

@pytest.mark.asyncio
async def test_login_success(client, seed_users, db):
    response = await client.post("/auth/login", json={
        "email": "user@test.com",
        "password": "userpass"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    
    # Verify cookies are set
    cookies = response.cookies
    assert "authkit_access" in cookies
    assert "authkit_refresh" in cookies
    
    # Verify session is created in DB
    stmt = select(RefreshToken).where(RefreshToken.user_id == "user-uuid-222")
    result = await db.execute(stmt)
    sessions = result.scalars().all()
    assert len(sessions) == 1
    assert not sessions[0].is_revoked

@pytest.mark.asyncio
async def test_login_invalid_password(client, seed_users):
    response = await client.post("/auth/login", json={
        "email": "user@test.com",
        "password": "wrongpassword"
    })
    assert response.status_code == 401
    assert "Incorrect email" in response.json()["detail"]

@pytest.mark.asyncio
async def test_login_deactivated_user(client, seed_users):
    response = await client.post("/auth/login", json={
        "email": "deactivated@test.com",
        "password": "userpass"
    })
    assert response.status_code == 403
    assert "deactivated" in response.json()["detail"]

@pytest.mark.asyncio
async def test_refresh_token_rotation(client, seed_users, db):
    # Log in first to get a refresh token
    login_resp = await client.post("/auth/login", json={
        "email": "user@test.com",
        "password": "userpass"
    })
    refresh_token = login_resp.json()["refresh_token"]
    
    # Call refresh endpoint passing the token as Bearer
    response = await client.post(
        "/auth/refresh", 
        headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    
    # Verify new cookies are set
    assert response.cookies.get("authkit_access") is not None
    
    # Verify old session is revoked and a new session is created in DB
    stmt = select(RefreshToken).where(RefreshToken.user_id == "user-uuid-222").order_by(RefreshToken.created_at.asc())
    result = await db.execute(stmt)
    sessions = result.scalars().all()
    assert len(sessions) == 2
    assert sessions[0].is_revoked is True  # old token revoked
    assert sessions[1].is_revoked is False # new token active

@pytest.mark.asyncio
async def test_logout(client, seed_users, db):
    # Log in
    login_resp = await client.post("/auth/login", json={
        "email": "user@test.com",
        "password": "userpass"
    })
    
    # Call logout
    response = await client.post("/auth/logout")
    assert response.status_code == 200
    
    # Cookies should be cleared (will have empty value or expired max-age)
    assert "authkit_access" not in response.cookies or response.cookies["authkit_access"] == ""
    
    # Database session should be marked as revoked
    stmt = select(RefreshToken).where(RefreshToken.user_id == "user-uuid-222")
    result = await db.execute(stmt)
    session = result.scalar_one_or_none()
    assert session.is_revoked is True

@pytest.mark.asyncio
async def test_logout_all(client, seed_users, db):
    # Log in multiple times (simulate multiple devices)
    login_1 = await client.post("/auth/login", json={"email": "user@test.com", "password": "userpass"})
    login_2 = await client.post("/auth/login", json={"email": "user@test.com", "password": "userpass"})
    
    access_token = login_2.json()["access_token"]
    
    # Confirm two active sessions exist
    stmt = select(RefreshToken).where(RefreshToken.user_id == "user-uuid-222", RefreshToken.is_revoked == False)
    result = await db.execute(stmt)
    assert len(result.scalars().all()) == 2
    
    # Call logout-all
    response = await client.post(
        "/auth/logout-all", 
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    
    # Confirm all sessions are revoked
    stmt_all = select(RefreshToken).where(RefreshToken.user_id == "user-uuid-222")
    res_all = await db.execute(stmt_all)
    sessions = res_all.scalars().all()
    assert len(sessions) == 2
    assert all(s.is_revoked for s in sessions)

@pytest.mark.asyncio
async def test_reset_password_flow(client, seed_users, db, auth_kit):
    # 1. Trigger forgot password request
    response = await client.post("/auth/forgot-password", json={
        "email": "user@test.com"
    })
    assert response.status_code == 200
    
    # Check that audit log has entry
    stmt_audit = select(AuditLog).where(AuditLog.user_id == "user-uuid-222")
    result_audit = await db.execute(stmt_audit)
    logs = result_audit.scalars().all()
    assert len(logs) == 1
    assert logs[0].action == "password_reset_requested"
    
    # Generate the token directly for testing reset endpoint
    stmt = select(User).where(User.id == "user-uuid-222")
    res = await db.execute(stmt)
    user = res.scalar_one()
    reset_token = auth_kit.auth_service.create_reset_token("user-uuid-222", user.hashed_password)
    
    # 2. Reset password using the token
    reset_resp = await client.post("/auth/reset-password", json={
        "token": reset_token,
        "new_password": "NewSuperSecret123!"
    })
    assert reset_resp.status_code == 200
    
    # 3. Test logging in with the new password
    login_resp = await client.post("/auth/login", json={
        "email": "user@test.com",
        "password": "NewSuperSecret123!"
    })
    assert login_resp.status_code == 200
    assert "access_token" in login_resp.json()

@pytest.mark.asyncio
async def test_reset_token_cannot_be_reused(client, seed_users, db, auth_kit):
    # Fetch user's current password hash
    stmt = select(User).where(User.id == "user-uuid-222")
    res = await db.execute(stmt)
    user = res.scalar_one()
    reset_token = auth_kit.auth_service.create_reset_token("user-uuid-222", user.hashed_password)
    
    # First reset - success
    reset_resp = await client.post("/auth/reset-password", json={
        "token": reset_token,
        "new_password": "NewSuperSecret123!"
    })
    assert reset_resp.status_code == 200
    
    # Second reset using the same token - should fail (used token)
    reset_resp2 = await client.post("/auth/reset-password", json={
        "token": reset_token,
        "new_password": "AnotherNewPass123!"
    })
    assert reset_resp2.status_code == 400
    assert "already been used" in reset_resp2.json()["detail"]

import pytest
from sqlalchemy import select
from authkit_fastapi.models import User, RefreshToken, AuditLog

@pytest.mark.asyncio
async def test_admin_dashboard_redirect_unauthenticated(client):
    # Try fetching dashboard without logging in
    response = await client.get("/admin/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert "/admin/login" in response.headers["location"]

@pytest.mark.asyncio
async def test_admin_dashboard_unauthorized_user(client, seed_users, auth_kit):
    # Log in as normal user
    access_token = auth_kit.auth_service.create_access_token("user-uuid-222", "user")
    
    # Attempt dashboard access
    client.cookies.set("authkit_access", access_token)
    response = await client.get("/admin/dashboard", follow_redirects=False)
    
    # Should redirect to login because role is not admin
    assert response.status_code == 303
    assert "/admin/login" in response.headers["location"]

@pytest.mark.asyncio
async def test_admin_dashboard_success(client, seed_users, auth_kit):
    # Log in as admin
    access_token = auth_kit.auth_service.create_access_token("admin-uuid-111", "admin")
    client.cookies.set("authkit_access", access_token)
    
    response = await client.get("/admin/dashboard")
    assert response.status_code == 200
    assert "User Database" in response.text
    assert "admin@test.com" in response.text
    assert "user@test.com" in response.text

@pytest.mark.asyncio
async def test_admin_login_post_success(client, seed_users):
    # Submit admin login form
    response = await client.post(
        "/admin/login", 
        data={"email": "admin@test.com", "password": "adminpass"},
        follow_redirects=False
    )
    assert response.status_code == 303
    assert "/admin/dashboard" in response.headers["location"]
    assert "authkit_access" in response.cookies

@pytest.mark.asyncio
async def test_admin_login_post_failure_role(client, seed_users):
    # Submit user credentials to admin login
    response = await client.post(
        "/admin/login", 
        data={"email": "user@test.com", "password": "userpass"}
    )
    assert response.status_code == 200
    assert "administrator credentials required" in response.text

@pytest.mark.asyncio
async def test_admin_toggle_user_active(client, seed_users, auth_kit, db):
    admin_token = auth_kit.auth_service.create_access_token("admin-uuid-111", "admin")
    client.cookies.set("authkit_access", admin_token)
    
    # Deactivate normal user
    response = await client.post(
        "/admin/users/user-uuid-222/toggle-active",
        json={"is_active": False}
    )
    assert response.status_code == 200
    assert response.json()["success"] is True
    
    # Verify user state in DB
    db.expire_all()
    stmt = select(User).where(User.id == "user-uuid-222")
    user = (await db.execute(stmt)).scalar_one()
    assert user.is_active is False

@pytest.mark.asyncio
async def test_admin_change_user_role(client, seed_users, auth_kit, db):
    admin_token = auth_kit.auth_service.create_access_token("admin-uuid-111", "admin")
    client.cookies.set("authkit_access", admin_token)
    
    # Change role to moderator
    response = await client.post(
        "/admin/users/user-uuid-222/change-role",
        json={"role": "moderator"}
    )
    assert response.status_code == 200
    assert response.json()["success"] is True
    
    # Verify DB
    db.expire_all()
    stmt = select(User).where(User.id == "user-uuid-222")
    user = (await db.execute(stmt)).scalar_one()
    assert user.role == "moderator"

@pytest.mark.asyncio
async def test_admin_revoke_session(client, seed_users, auth_kit, db):
    admin_token = auth_kit.auth_service.create_access_token("admin-uuid-111", "admin")
    client.cookies.set("authkit_access", admin_token)
    
    # Create a user session
    session = await auth_kit.auth_service.create_session(
        db=db,
        user_id="user-uuid-222",
        jti="test-session-jti",
        token="some-refresh-token"
    )
    session_id = session.id
    
    # Revoke session via admin route
    response = await client.post(f"/admin/sessions/{session_id}/revoke")
    assert response.status_code == 200
    assert response.json()["success"] is True
    
    # Verify DB
    db.expire_all()
    stmt = select(RefreshToken).where(RefreshToken.id == session_id)
    refreshed_session = (await db.execute(stmt)).scalar_one()
    assert refreshed_session.is_revoked is True

@pytest.mark.asyncio
async def test_admin_delete_user(client, seed_users, auth_kit, db):
    admin_token = auth_kit.auth_service.create_access_token("admin-uuid-111", "admin")
    client.cookies.set("authkit_access", admin_token)
    
    # Delete normal user
    response = await client.post("/admin/users/user-uuid-222/delete")
    assert response.status_code == 200
    assert response.json()["success"] is True
    
    # Verify user is gone
    db.expire_all()
    stmt = select(User).where(User.id == "user-uuid-222")
    assert (await db.execute(stmt)).scalar_one_or_none() is None

@pytest.mark.asyncio
async def test_admin_cannot_revoke_own_session(client, seed_users, auth_kit, db):
    admin_token = auth_kit.auth_service.create_access_token("admin-uuid-111", "admin")
    client.cookies.set("authkit_access", admin_token)
    
    # Create the admin's active session
    session = await auth_kit.auth_service.create_session(
        db=db,
        user_id="admin-uuid-111",
        jti="admin-session-jti",
        token="admin-refresh-token"
    )
    session_id = session.id
    
    # Set the refresh token cookie matching the session's jti
    refresh_token = auth_kit.auth_service.create_refresh_token("admin-uuid-111", "admin-session-jti")
    client.cookies.set("authkit_refresh", refresh_token)
    
    # Attempt to revoke own session
    response = await client.post(f"/admin/sessions/{session_id}/revoke")
    assert response.status_code == 400
    assert "Cannot revoke your own active session" in response.json()["detail"]
    
    # Verify DB: session must not be revoked
    db.expire_all()
    stmt = select(RefreshToken).where(RefreshToken.id == session_id)
    refreshed_session = (await db.execute(stmt)).scalar_one()
    assert refreshed_session.is_revoked is False

@pytest.mark.asyncio
async def test_admin_revoked_session_logout(client, seed_users, auth_kit, db):
    admin_token = auth_kit.auth_service.create_access_token("admin-uuid-111", "admin")
    client.cookies.set("authkit_access", admin_token)
    
    # Create session
    session = await auth_kit.auth_service.create_session(
        db=db,
        user_id="admin-uuid-111",
        jti="admin-session-jti-2",
        token="admin-refresh-token-2"
    )
    
    refresh_token = auth_kit.auth_service.create_refresh_token("admin-uuid-111", "admin-session-jti-2")
    client.cookies.set("authkit_refresh", refresh_token)
    
    # First access - success
    response = await client.get("/admin/dashboard")
    assert response.status_code == 200
    
    # Revoke the session in database
    session_id = session.id
    db.expire_all()
    stmt = select(RefreshToken).where(RefreshToken.id == session_id)
    session_db = (await db.execute(stmt)).scalar_one()
    session_db.is_revoked = True
    await db.commit()
    
    # Second access - should fail auth check, clear cookies, and redirect to login
    response = await client.get("/admin/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert "/admin/login" in response.headers["location"]

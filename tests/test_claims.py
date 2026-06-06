import pytest
import jwt
import uuid
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from authkit_fastapi import AuthKit, AuthKitConfig
from authkit_fastapi.models_concrete import User, RefreshToken, AuditLog

@pytest.mark.asyncio
async def test_access_token_claims_hook_direct(test_session_maker):
    # 1. Define custom claims callback
    def custom_claims(user):
        return {
            "hotel_id": "999",
            "department": "engineering",
            "aud": "my-app-audience"
        }

    # 2. Initialize config with the custom claims callback
    config = AuthKitConfig(
        secret_key="claims-test-secret-key",
        cookie_secure=False,
        cookie_samesite="lax",
        enable_register=True,
        enable_audit_logs=True,
        access_token_claims=custom_claims
    )

    auth_kit = AuthKit(
        config=config,
        db_session_maker=test_session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        audit_log_model=AuditLog
    )

    # Test direct service call with MockUser object
    class MockUser:
        id = "11111111-1111-4111-a111-111111111111"
        role = "admin"
        email = "admin@test.com"

    mock_user = MockUser()
    token = auth_kit.auth_service.create_access_token(mock_user)
    
    # Decode token and verify claims (specifying expected audience)
    payload = jwt.decode(token, config.secret_key, audience="my-app-audience", algorithms=[config.algorithm])
    assert payload["sub"] == mock_user.id
    assert payload["app_role"] == "admin"
    assert payload["hotel_id"] == "999"
    assert payload["department"] == "engineering"
    assert payload["aud"] == "my-app-audience"


@pytest.mark.asyncio
async def test_access_token_claims_hook_api(test_session_maker):
    # 1. Define custom claims callback
    def custom_claims(user):
        # Verify that the user passed is indeed a User instance (with email attribute)
        assert hasattr(user, "email")
        return {
            "hotel_id": "888",
            "roles_list": ["user", "hotel-admin"]
        }

    # 2. Initialize config with the custom claims callback
    config = AuthKitConfig(
        secret_key="claims-test-secret-key",
        cookie_secure=False,
        cookie_samesite="lax",
        enable_register=True,
        enable_audit_logs=True,
        access_token_claims=custom_claims
    )

    auth_kit = AuthKit(
        config=config,
        db_session_maker=test_session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        audit_log_model=AuditLog
    )

    app = FastAPI()
    app.include_router(auth_kit.router, prefix="/auth")

    # Seed user in DB
    async with test_session_maker() as session:
        user_pw = auth_kit.auth_service.hash_password("userpass")
        user = User(
            id=uuid.UUID("22222222-2222-4222-a222-222222222222"),
            email="claims_user@test.com",
            hashed_password=user_pw,
            role="user",
            is_active=True,
            is_verified=True
        )
        session.add(user)
        await session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # A. Test login endpoint
        response = await ac.post("/auth/login", json={
            "email": "claims_user@test.com",
            "password": "userpass"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        
        # Decode and assert claims
        payload = jwt.decode(data["access_token"], config.secret_key, algorithms=[config.algorithm])
        assert payload["sub"] == "22222222-2222-4222-a222-222222222222"
        assert payload["app_role"] == "user"
        assert payload["hotel_id"] == "888"
        assert payload["roles_list"] == ["user", "hotel-admin"]

        # B. Test refresh token endpoint (rotation)
        refresh_token = data["refresh_token"]
        refresh_response = await ac.post(
            "/auth/refresh", 
            headers={"Authorization": f"Bearer {refresh_token}"}
        )
        assert refresh_response.status_code == 200
        refresh_data = refresh_response.json()
        assert "access_token" in refresh_data
        
        # Decode new access token and assert custom claims are still present
        new_payload = jwt.decode(refresh_data["access_token"], config.secret_key, algorithms=[config.algorithm])
        assert new_payload["sub"] == "22222222-2222-4222-a222-222222222222"
        assert new_payload["app_role"] == "user"
        assert new_payload["hotel_id"] == "888"
        assert new_payload["roles_list"] == ["user", "hotel-admin"]


@pytest.mark.asyncio
async def test_access_token_claims_hook_audience_config(test_session_maker):
    # Test that setting jwt_audience config correctly validates audience on decode
    def custom_claims(user):
        return {
            "aud": "my-app-audience"
        }

    config = AuthKitConfig(
        secret_key="claims-test-secret-key",
        cookie_secure=False,
        cookie_samesite="lax",
        enable_register=True,
        enable_audit_logs=True,
        access_token_claims=custom_claims,
        jwt_audience="my-app-audience"
    )

    auth_kit = AuthKit(
        config=config,
        db_session_maker=test_session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        audit_log_model=AuditLog
    )

    class MockUser:
        id = "11111111-1111-4111-a111-111111111111"
        role = "admin"

    mock_user = MockUser()
    token = auth_kit.auth_service.create_access_token(mock_user)
    
    # 1. Decode with correct audience via decode_token (should succeed)
    payload = auth_kit.auth_service.decode_token(token)
    assert payload is not None
    assert payload["aud"] == "my-app-audience"

    # 2. Decode with incorrect expected audience should fail
    payload_bad = auth_kit.auth_service.decode_token(token, audience="wrong-audience")
    assert payload_bad is None


@pytest.mark.asyncio
async def test_requires_role_dependencies(test_session_maker):
    # 1. Initialize AuthKit
    config = AuthKitConfig(
        secret_key="claims-test-secret-key",
        cookie_secure=False,
        cookie_samesite="lax",
        enable_register=True,
        enable_audit_logs=True
    )

    auth_kit = AuthKit(
        config=config,
        db_session_maker=test_session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        audit_log_model=AuditLog
    )

    app = FastAPI()
    app.include_router(auth_kit.router, prefix="/auth")

    # 2. Add route requiring role "moderator"
    from fastapi import Depends
    @app.get("/moderation")
    def moderation_route(user=Depends(auth_kit.requires_role("moderator"))):
        return {"status": "success", "user_email": user.email}

    # 3. Add route requiring roles "admin" or "editor"
    @app.get("/editorial")
    def editorial_route(user=Depends(auth_kit.requires_roles(["admin", "editor"]))):
        return {"status": "success", "user_email": user.email}

    # 4. Seed users in DB
    async with test_session_maker() as session:
        user_pw = auth_kit.auth_service.hash_password("userpass")
        u_regular = User(
            id=uuid.UUID("22222222-2222-4222-a222-222222222222"),
            email="regular@test.com",
            hashed_password=user_pw,
            role="user",
            is_active=True,
            is_verified=True
        )
        u_mod = User(
            id=uuid.UUID("33333333-3333-4333-a333-333333333333"),
            email="mod@test.com",
            hashed_password=user_pw,
            role="moderator",
            is_active=True,
            is_verified=True
        )
        u_admin = User(
            id=uuid.UUID("44444444-4444-4444-a444-444444444444"),
            email="admin@test.com",
            hashed_password=user_pw,
            role="admin",
            is_active=True,
            is_verified=True
        )
        session.add_all([u_regular, u_mod, u_admin])
        await session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # A. Login as regular user
        login_reg = await ac.post("/auth/login", json={
            "email": "regular@test.com",
            "password": "userpass"
        })
        token_reg = login_reg.json()["access_token"]

        # B. Login as moderator
        login_mod = await ac.post("/auth/login", json={
            "email": "mod@test.com",
            "password": "userpass"
        })
        token_mod = login_mod.json()["access_token"]

        # C. Login as admin
        login_admin = await ac.post("/auth/login", json={
            "email": "admin@test.com",
            "password": "userpass"
        })
        token_admin = login_admin.json()["access_token"]

        # Clear cookies from the client so they don't override the Authorization header
        ac.cookies.clear()

        # Test route: /moderation
        # Regular user tries to access /moderation (should get 403)
        res1 = await ac.get("/moderation", headers={"Authorization": f"Bearer {token_reg}"})
        assert res1.status_code == 403
        assert "Access forbidden" in res1.json()["detail"]

        # Moderator tries to access /moderation (should get 200)
        res2 = await ac.get("/moderation", headers={"Authorization": f"Bearer {token_mod}"})
        assert res2.status_code == 200
        assert res2.json()["status"] == "success"

        # Test route: /editorial
        # Regular user tries to access /editorial (should get 403)
        res3 = await ac.get("/editorial", headers={"Authorization": f"Bearer {token_reg}"})
        assert res3.status_code == 403

        # Moderator tries to access /editorial (should get 403)
        res4 = await ac.get("/editorial", headers={"Authorization": f"Bearer {token_mod}"})
        assert res4.status_code == 403

        # Admin tries to access /editorial (should get 200)
        res5 = await ac.get("/editorial", headers={"Authorization": f"Bearer {token_admin}"})
        assert res5.status_code == 200
        assert res5.json()["status"] == "success"

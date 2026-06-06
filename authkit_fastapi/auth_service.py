import hashlib
import jwt
import bcrypt
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

class AuthService:
    """Handles password hashing, token generation, decoding, and database-backed session state."""
    
    def __init__(self, config, user_model, refresh_token_model, audit_log_model):
        self.config = config
        self.user_model = user_model
        self.refresh_token_model = refresh_token_model
        self.audit_log_model = audit_log_model

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        # bcrypt.gensalt() generates a random salt. Hashing is a CPU-bound operation.
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against a bcrypt hash."""
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
        except Exception:
            return False

    def create_access_token(self, user: Any, role: Optional[str] = None) -> str:
        """Generate a short-lived access JWT."""
        user_id = user.id if hasattr(user, "id") else user
        user_role = getattr(user, "role", None)
        if user_role is None:
            user_role = role or "user"

        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id),
            "app_role": user_role,
            "exp": now + timedelta(minutes=self.config.access_token_expire_minutes),
            "iat": now,
            "type": "access"
        }
        if getattr(self.config, "access_token_claims", None) is not None:
            custom_claims = self.config.access_token_claims(user)
            if custom_claims:
                payload.update(custom_claims)
        return jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)

    def create_refresh_token(self, user_id: Any, jti: str) -> str:
        """Generate a long-lived refresh JWT."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id),
            "jti": jti,
            "exp": now + timedelta(days=self.config.refresh_token_expire_days),
            "iat": now,
            "type": "refresh"
        }
        return jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)

    def create_reset_token(self, user_id: Any, password_hash: str) -> str:
        """Generate a short-lived reset-password JWT, bound to the user's current password hash."""
        now = datetime.now(timezone.utc)
        import hashlib
        token_pwd_sec = hashlib.sha256(password_hash.encode()).hexdigest()[:16]
        payload = {
            "sub": str(user_id),
            "action": "reset_password",
            "pwd_sec": token_pwd_sec,
            "exp": now + timedelta(minutes=15),
            "iat": now
        }
        return jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)

    def decode_token(self, token: str, audience: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Decode and validate a JWT. Returns payload or None if invalid."""
        try:
            kwargs = {}
            aud = audience or getattr(self.config, "jwt_audience", None)
            if aud:
                kwargs["audience"] = aud
            else:
                kwargs["options"] = {"verify_aud": False}
            return jwt.decode(token, self.config.secret_key, algorithms=[self.config.algorithm], **kwargs)
        except jwt.PyJWTError:
            return None

    def hash_token(self, token: str) -> str:
        """Hash a token value for secure database storage using SHA-256."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def create_session(
        self,
        db: AsyncSession,
        user_id: str,
        jti: str,
        token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Any:
        """Record a new active refresh token session in the database."""
        # Calculate expiration timezone-aware consistently
        expires_at = datetime.now(timezone.utc) + timedelta(days=self.config.refresh_token_expire_days)
        token_hash = self.hash_token(token)
        
        session = self.refresh_token_model(
            user_id=user_id,
            jti=jti,
            token_hash=token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            is_revoked=False
        )
        db.add(session)
        await db.commit()
        await db.refresh(session)
        return session

    async def verify_session(self, db: AsyncSession, jti: str, token: str) -> Optional[Any]:
        """Verify that a session exists in the database, is not revoked, and matches the token hash."""
        stmt = select(self.refresh_token_model).where(
            self.refresh_token_model.jti == jti,
            self.refresh_token_model.is_revoked == False
        )
        result = await db.execute(stmt)
        session = result.scalar_one_or_none()
        if not session:
            return None
            
        # Check expiration date
        now = datetime.now(timezone.utc)
        db_expire = session.expires_at
        if db_expire is not None:
            if db_expire.tzinfo is None:
                db_expire = db_expire.replace(tzinfo=timezone.utc)
            if now > db_expire:
                return None
            
        # Verify hash match
        if session.token_hash != self.hash_token(token):
            return None
            
        return session

    async def revoke_session(self, db: AsyncSession, jti: str) -> bool:
        """Revoke a specific session by its JTI."""
        stmt = select(self.refresh_token_model).where(self.refresh_token_model.jti == jti)
        result = await db.execute(stmt)
        session = result.scalar_one_or_none()
        if session and not session.is_revoked:
            session.is_revoked = True
            await db.commit()
            return True
        return False

    async def revoke_all_sessions(self, db: AsyncSession, user_id: str) -> None:
        """Revoke all active sessions for a given user."""
        stmt = select(self.refresh_token_model).where(
            self.refresh_token_model.user_id == user_id,
            self.refresh_token_model.is_revoked == False
        )
        result = await db.execute(stmt)
        sessions = result.scalars().all()
        for session in sessions:
            session.is_revoked = True
        await db.commit()

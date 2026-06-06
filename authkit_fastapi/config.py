from typing import Optional, Callable, Any, Dict
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class AuthKitConfig(BaseSettings):
    """Configuration settings for AuthKit.
    
    Can be loaded from environment variables prefixed with AUTHKIT_
    or passed directly during instantiation.
    """
    model_config = SettingsConfigDict(env_prefix="authkit_", env_file=".env", env_file_encoding="utf-8", extra="ignore")

    secret_key: str = Field(default="dev-secret-change-me-in-production-1234567890!")
    algorithm: str = Field(default="HS256")
    jwt_audience: Optional[str] = Field(default=None)
    
    # Token expiration times
    access_token_expire_minutes: int = Field(default=15)
    refresh_token_expire_days: int = Field(default=7)
    
    # Cookie Configuration
    cookie_name_access: str = Field(default="authkit_access")
    cookie_name_refresh: str = Field(default="authkit_refresh")
    cookie_secure: bool = Field(default=False)  # Set to True in production
    cookie_samesite: str = Field(default="lax")  # "lax", "strict", or "none"
    cookie_domain: Optional[str] = Field(default=None)
    
    # Features Toggles
    enable_register: bool = Field(default=True)
    enable_audit_logs: bool = Field(default=True)
    
    # Admin Interface Path
    admin_path: str = Field(default="/admin")
    admin_role: str = Field(default="admin")
    
    # Email Settings (for Reset Password)
    enable_smtp: bool = Field(default=False)
    smtp_host: Optional[str] = Field(default=None)
    smtp_port: int = Field(default=587)
    smtp_username: Optional[str] = Field(default=None)
    smtp_password: Optional[str] = Field(default=None)
    smtp_from_email: Optional[str] = Field(default=None)
    
    # Custom Callback for email sending (alternative to SMTP)
    # Signature: async def send_email(email: str, subject: str, body_text: str, body_html: str) -> None
    email_sender_callback: Optional[Callable[[str, str, str, str], Any]] = Field(default=None, exclude=True)

    # Custom callback to inject extra claims into the access token payload.
    # Signature: Optional[Callable[[Any], Dict[str, Any]]]
    access_token_claims: Optional[Callable[[Any], Dict[str, Any]]] = Field(default=None, exclude=True)

import sys
from typing import Optional, Dict, Any
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

class AuditService:
    """Handles writing structured audit logs to the database."""
    
    def __init__(self, config, audit_log_model):
        self.config = config
        self.audit_log_model = audit_log_model

    async def log_action(
        self,
        db: AsyncSession,
        action: str,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        request: Optional[Request] = None
    ) -> Optional[Any]:
        """Record a structured audit log entry to the database.
        
        Extracts client IP (with reverse proxy header checks) and User Agent from request.
        """
        if not self.config.enable_audit_logs:
            return None

        ip_address = None
        user_agent = None

        if request:
            # Extract IP addressing, checking for standard reverse proxy headers
            x_forwarded_for = request.headers.get("x-forwarded-for")
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(",")[0].strip()
            elif request.client:
                ip_address = request.client.host
                
            user_agent = request.headers.get("user-agent")

        try:
            log_entry = self.audit_log_model(
                user_id=user_id,
                action=action,
                details=details,
                ip_address=ip_address,
                user_agent=user_agent
            )
            db.add(log_entry)
            await db.commit()
            return log_entry
        except Exception as e:
            print(f"[AuthKit] Failed to write audit log: {e}", file=sys.stderr)
            return None

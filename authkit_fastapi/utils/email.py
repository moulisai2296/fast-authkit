import smtplib
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

class EmailService:
    """Handles sending transactional emails (e.g. password resets, verification)."""
    
    def __init__(self, config):
        self.config = config

    async def send_email(self, recipient: str, subject: str, body_text: str, body_html: str) -> bool:
        """Send an email using custom callback, SMTP, or console logs in fallback mode."""
        # 1. Custom callback has first priority
        if self.config.email_sender_callback:
            try:
                if asyncio.iscoroutinefunction(self.config.email_sender_callback):
                    await self.config.email_sender_callback(recipient, subject, body_text, body_html)
                else:
                    self.config.email_sender_callback(recipient, subject, body_text, body_html)
                return True
            except Exception as e:
                # We log but do not raise, so we can gracefully return failure status
                import sys
                print(f"[AuthKit] Custom email callback failed: {e}", file=sys.stderr)
                return False

        # 2. SMTP has second priority
        if self.config.enable_smtp and self.config.smtp_host:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None, 
                    self._send_smtp, 
                    recipient, 
                    subject, 
                    body_text, 
                    body_html
                )
                return True
            except Exception as e:
                import sys
                print(f"[AuthKit] SMTP connection/send failed: {e}", file=sys.stderr)
                return False

        # 3. Default fallback: Print to console (excellent for local sandbox development)
        print("\n" + "="*60)
        print(f"[AuthKit Sandbox Email]")
        print(f"Recipient: {recipient}")
        print(f"Subject:   {subject}")
        print(f"Message (Text):\n{body_text}")
        print("="*60 + "\n")
        return True

    def _send_smtp(self, recipient: str, subject: str, body_text: str, body_html: str) -> None:
        """Synchronous SMTP sending executed within a thread pool executor."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        sender = self.config.smtp_from_email or self.config.smtp_username or "no-reply@authkit.local"
        msg["From"] = sender
        msg["To"] = recipient

        part1 = MIMEText(body_text, "plain", "utf-8")
        part2 = MIMEText(body_html, "html", "utf-8")
        msg.attach(part1)
        msg.attach(part2)

        server = smtplib.SMTP(self.config.smtp_host, self.config.smtp_port)
        try:
            if self.config.smtp_username and self.config.smtp_password:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.config.smtp_username, self.config.smtp_password)
            server.sendmail(sender, [recipient], msg.as_string())
        finally:
            server.quit()

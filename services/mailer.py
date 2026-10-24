import smtplib
import secrets
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import Config
from database import get_db


def send_real_email(recipient: str, subject: str, html_body: str) -> tuple[bool, str]:
    if not Config.SMTP_USER or not Config.SMTP_PASSWORD:
        return False, "Не налаштовано SMTP_USER та SMTP_PASSWORD у файлі .env"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = Config.SMTP_FROM
    msg["To"] = recipient
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        if Config.SMTP_PORT == 465:
            with smtplib.SMTP_SSL(Config.SMTP_HOST, Config.SMTP_PORT, timeout=15) as server:
                server.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
                server.send_message(msg)
        return True, "OK"
    except Exception as e:
        return False, str(e)


def create_token(user_id: int, token_type: str, ttl_minutes: int) -> tuple[str, str]:
    db = get_db()
    db.execute(
        "UPDATE security_tokens SET used = 1 WHERE user_id = ? AND token_type = ? AND used = 0",
        (user_id, token_type)
    )
    token = secrets.token_urlsafe(24)
    now = datetime.now()
    expires_str = (now + timedelta(minutes=ttl_minutes)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute("""
        INSERT INTO security_tokens (user_id, token, token_type, expires_at, used, created_at)
        VALUES (?, ?, ?, ?, 0, ?)
    """, (user_id, token, token_type, expires_str, now.strftime("%Y-%m-%d %H:%M:%S")))
    db.commit()
    return token, expires_str

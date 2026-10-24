import sqlite3
from datetime import datetime
from flask import g, request
from config import Config
from services.security import hash_password, generate_totp_secret


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(Config.DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(Config.DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 0,
            is_locked_by_admin INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT DEFAULT NULL,
            two_fa_enabled INTEGER NOT NULL DEFAULT 0,
            two_fa_method TEXT NOT NULL DEFAULT 'totp',
            totp_secret TEXT DEFAULT NULL,
            email_otp_code TEXT DEFAULT NULL,
            email_otp_expires TEXT DEFAULT NULL,
            oauth_provider TEXT DEFAULT NULL,
            oauth_sub TEXT DEFAULT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            token_type TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_or_email TEXT NOT NULL,
            user_id INTEGER DEFAULT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            event_type TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    if Config.ADMIN_PASSWORD:
        cur.execute("SELECT id FROM users WHERE username = ?", (Config.ADMIN_USERNAME,))
        if not cur.fetchone():
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur.execute("""
                INSERT INTO users (
                    username, email, password_hash, role, is_active,
                    is_locked_by_admin, failed_attempts, two_fa_enabled,
                    two_fa_method, totp_secret, created_at
                ) VALUES (?, ?, ?, 'admin', 1, 0, 0, 0, 'totp', ?, ?)
            """, (
                Config.ADMIN_USERNAME,
                Config.ADMIN_EMAIL,
                hash_password(Config.ADMIN_PASSWORD),
                generate_totp_secret(),
                now_str
            ))

    conn.commit()
    conn.close()


def log_event(username_or_email: str, event_type: str, status: str, details: str, user_id: int = None):
    db = get_db()
    ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1"
    ua = (request.headers.get("User-Agent") or "Unknown")[:150]
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.execute("""
        INSERT INTO login_logs (username_or_email, user_id, ip_address, user_agent, event_type, status, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (username_or_email, user_id, ip_addr, ua, event_type, status, details, now_str))
    db.commit()

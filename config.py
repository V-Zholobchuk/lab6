import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_dotenv_file(filepath):
    if not os.path.exists(filepath):
        return
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip().strip('"').strip("'")
            os.environ[k.strip()] = v


load_dotenv_file(os.path.join(BASE_DIR, ".env"))


class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
    DB_PATH = os.path.join(BASE_DIR, os.environ.get("DB_NAME", "auth_system.db"))

    MAX_FAILED_ATTEMPTS = int(os.environ.get("MAX_FAILED_ATTEMPTS", "3"))
    LOCKOUT_MINUTES = int(os.environ.get("LOCKOUT_MINUTES", "15"))
    ACTIVATION_TTL_MIN = 30
    RESET_TTL_MIN = 15
    OTP_TTL_MIN = 5

    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

    SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587").strip() or "587")
    SMTP_USER = os.environ.get("SMTP_USER", "").strip()
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()
    SMTP_FROM = os.environ.get("SMTP_FROM", "").strip() or SMTP_USER

    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "").strip()
    GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "").strip()

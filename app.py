import os
import re
import hmac
import time
import json
import base64
import struct
import random
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g
)

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
            os.environ.setdefault(k.strip(), v.strip())


load_dotenv_file(os.path.join(BASE_DIR, ".env"))

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

DB_PATH = os.path.join(BASE_DIR, os.environ.get("DB_NAME", "auth_system.db"))

MAX_FAILED_ATTEMPTS = int(os.environ.get("MAX_FAILED_ATTEMPTS", "3"))
LOCKOUT_MINUTES = int(os.environ.get("LOCKOUT_MINUTES", "15"))
ACTIVATION_TTL_MIN = 30
RESET_TTL_MIN = 15
OTP_TTL_MIN = 5

WEAK_PASSWORDS = {
    "password", "password1!", "password123!", "qwerty123!", "qwertyui1!",
    "admin123!", "12345678a!", "12345678aa!", "welcome1!"
}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(password: str, salt: str = None) -> str:
    iterations = 600000
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations
    )
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        _, iter_str, salt, hex_digest = stored_hash.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iter_str)
        )
        return hmac.compare_digest(dk.hex(), hex_digest)
    except Exception:
        return False


def validate_password_policy(password: str, username: str = "") -> tuple[bool, list[str]]:
    errors = []
    if len(password) < 8:
        errors.append("Довжина пароля має бути не менше 8 символів.")
    if not (any(c.isupper() for c in password) and any(c.islower() for c in password)):
        errors.append("Пароль має містити великі та малі літери.")
    if not any(c.isdigit() for c in password):
        errors.append("Пароль має містити хоча б одну цифру.")
    if not any(not c.isalnum() for c in password):
        errors.append("Пароль має містити спеціальний символ (не літеру і не цифру).")

    low = password.lower()
    if low in WEAK_PASSWORDS or "123456" in low or "qwerty" in low or "password" in low:
        errors.append("Пароль занадто простий або поширений.")
    if username and len(username) >= 3 and username.lower() in low:
        errors.append("Пароль не повинен містити логін користувача.")

    return len(errors) == 0, errors


def generate_totp_secret(length: int = 16) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def get_totp_token(secret: str, time_step: int = 30, offset: int = 0) -> str:
    key = base64.b32decode(secret.upper(), casefold=True)
    counter = int(time.time() // time_step) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    pos = digest[19] & 0x0F
    code = (struct.unpack(">I", digest[pos:pos + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    clean = code.strip().replace(" ", "")
    for step in (-1, 0, 1):
        if hmac.compare_digest(get_totp_token(secret, offset=step), clean):
            return True
    return False


def generate_captcha_svg() -> tuple[str, str]:
    chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    code = "".join(secrets.choice(chars) for _ in range(5))
    w, h = 180, 50
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
        f'style="background:#f1f5f9; border:1px solid #cbd5e1; border-radius:4px;">'
    ]
    for _ in range(5):
        x1, y1 = random.randint(0, w), random.randint(0, h)
        x2, y2 = random.randint(0, w), random.randint(0, h)
        parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#94a3b8" stroke-width="1.2"/>')

    for i, ch in enumerate(code):
        x = 20 + i * 30 + random.randint(-2, 2)
        y = 33 + random.randint(-4, 4)
        rot = random.randint(-18, 18)
        parts.append(
            f'<text x="{x}" y="{y}" fill="#1e293b" font-family="monospace" font-size="24" font-weight="bold" '
            f'transform="rotate({rot} {x} {y})">{ch}</text>'
        )
    parts.append("</svg>")
    b64 = base64.b64encode("".join(parts).encode("utf-8")).decode("ascii")
    return code, f"data:image/svg+xml;base64,{b64}"


def init_db():
    conn = sqlite3.connect(DB_PATH)
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

    cur.execute("""
        CREATE TABLE IF NOT EXISTS sent_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_html TEXT NOT NULL,
            action_url TEXT DEFAULT NULL,
            token_type TEXT DEFAULT NULL,
            expires_at TEXT DEFAULT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    admin_user = os.environ.get("ADMIN_USERNAME", "admin")
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    admin_pwd = os.environ.get("ADMIN_PASSWORD")

    if admin_pwd:
        cur.execute("SELECT id FROM users WHERE username = ?", (admin_user,))
        if not cur.fetchone():
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur.execute("""
                INSERT INTO users (
                    username, email, password_hash, role, is_active,
                    is_locked_by_admin, failed_attempts, two_fa_enabled,
                    two_fa_method, totp_secret, created_at
                ) VALUES (?, ?, ?, 'admin', 1, 0, 0, 0, 'totp', ?, ?)
            """, (admin_user, admin_email, hash_password(admin_pwd), generate_totp_secret(), now_str))

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


def send_email(recipient: str, subject: str, body_html: str, action_url: str = None, token_type: str = None, expires_at: str = None):
    db = get_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.execute("""
        INSERT INTO sent_emails (recipient, subject, body_html, action_url, token_type, expires_at, is_read, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?)
    """, (recipient, subject, body_html, action_url, token_type, expires_at, now_str))
    db.commit()


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


def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


@app.context_processor
def inject_globals():
    user = get_current_user()
    unread = get_db().execute("SELECT COUNT(*) AS cnt FROM sent_emails WHERE is_read = 0").fetchone()["cnt"]
    return dict(current_user=user, unread_emails_count=unread)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Увійдіть у систему.", "warning")
            return redirect(url_for("login"))
        if user["is_locked_by_admin"]:
            session.clear()
            flash("Обліковий запис заблоковано адміністратором.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            log_event(user["username"], "RBAC_DENIED", "DENIED", "Спроба доступу до адмін-панелі", user["id"])
            flash("Доступ дозволено лише адміністратору.", "danger")
            return redirect(url_for("profile"))
        return f(*args, **kwargs)
    return wrapper


@app.route("/")
def index():
    return redirect(url_for("profile") if get_current_user() else url_for("login"))


@app.route("/captcha/refresh")
def refresh_captcha():
    code, svg_uri = generate_captcha_svg()
    session["captcha_code"] = code
    return {"svg_uri": svg_uri}


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        captcha_in = request.form.get("captcha", "").strip().upper()

        expected_captcha = session.get("captcha_code", "")
        new_code, new_svg = generate_captcha_svg()
        session["captcha_code"] = new_code

        if not expected_captcha or captcha_in != expected_captcha.upper():
            log_event(username or email or "guest", "CAPTCHA_FAIL", "FAILED", "Невірна CAPTCHA при реєстрації")
            flash("Невірний код CAPTCHA.", "danger")
            return render_template("register.html", captcha_svg=new_svg, form_data=request.form)

        if len(username) < 3 or not re.match(r"^[a-zA-Z0-9_.-]+$", username):
            flash("Некоректний логін (мінімум 3 символи: латиниця, цифри, _ . -).", "danger")
            return render_template("register.html", captcha_svg=new_svg, form_data=request.form)

        if "@" not in email or "." not in email:
            flash("Введіть коректний email.", "danger")
            return render_template("register.html", captcha_svg=new_svg, form_data=request.form)

        if password != confirm:
            flash("Паролі не збігаються.", "danger")
            return render_template("register.html", captcha_svg=new_svg, form_data=request.form)

        valid_pwd, pwd_errors = validate_password_policy(password, username)
        if not valid_pwd:
            for err in pwd_errors:
                flash(err, "danger")
            log_event(username, "WEAK_PASSWORD", "FAILED", "; ".join(pwd_errors))
            return render_template("register.html", captcha_svg=new_svg, form_data=request.form)

        db = get_db()
        if db.execute("SELECT id FROM users WHERE lower(username)=lower(?) OR lower(email)=lower(?)", (username, email)).fetchone():
            flash("Користувач із таким логіном або email вже існує.", "danger")
            return render_template("register.html", captcha_svg=new_svg, form_data=request.form)

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur = db.execute("""
            INSERT INTO users (
                username, email, password_hash, role, is_active,
                is_locked_by_admin, failed_attempts, two_fa_enabled,
                two_fa_method, totp_secret, created_at
            ) VALUES (?, ?, ?, 'user', 0, 0, 0, 0, 'totp', ?, ?)
        """, (username, email, hash_password(password), generate_totp_secret(), now_str))
        user_id = cur.lastrowid
        db.commit()

        token, expires_str = create_token(user_id, "activation", ACTIVATION_TTL_MIN)
        act_url = url_for("activate_account", token=token, _external=True)

        body = (
            f"<p>Вітаємо, <b>{username}</b>!</p>"
            f"<p>Для активації акаунта перейдіть за посиланням: <a href='{act_url}'>{act_url}</a></p>"
            f"<p>Одноразовий токен: <code>{token}</code> (діє до {expires_str}).</p>"
        )
        send_email(email, "Активація облікового запису", body, act_url, "Активація", expires_str)
        log_event(username, "REGISTER", "SUCCESS", f"Реєстрація ({email}), надіслано токен активації", user_id)

        flash("Реєстрація успішна. Лист для активації надіслано (див. вкладку «Листи»).", "success")
        return redirect(url_for("login"))

    code, svg_uri = generate_captcha_svg()
    session["captcha_code"] = code
    return render_template("register.html", captcha_svg=svg_uri, form_data={})


@app.route("/activate/<token>")
def activate_account(token):
    db = get_db()
    row = db.execute("SELECT * FROM security_tokens WHERE token = ? AND token_type = 'activation'", (token,)).fetchone()
    if not row:
        flash("Недійсний токен активації.", "danger")
        return redirect(url_for("login"))
    if row["used"] == 1:
        flash("Токен вже використано.", "warning")
        return redirect(url_for("login"))
    if datetime.now() > datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S"):
        flash("Термін дії токена минув.", "danger")
        return redirect(url_for("login"))

    db.execute("UPDATE security_tokens SET used = 1 WHERE id = ?", (row["id"],))
    db.execute("UPDATE users SET is_active = 1 WHERE id = ?", (row["user_id"],))
    db.commit()

    user = db.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
    log_event(user["username"], "ACTIVATE", "SUCCESS", "Акаунт активовано за токеном", user["id"])
    flash("Обліковий запис успішно активовано.", "success")
    return redirect(url_for("profile") if session.get("user_id") else url_for("login"))


@app.route("/resend-activation", methods=["POST"])
@login_required
def resend_activation():
    user = get_current_user()
    if not user["is_active"]:
        token, expires_str = create_token(user["id"], "activation", ACTIVATION_TTL_MIN)
        act_url = url_for("activate_account", token=token, _external=True)
        body = f"<p>Нове посилання для активації: <a href='{act_url}'>{act_url}</a></p><p>Діє до: {expires_str}</p>"
        send_email(user["email"], "Повторна активація акаунта", body, act_url, "Активація", expires_str)
        flash("Новий лист активації надіслано.", "info")
    return redirect(url_for("profile"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE lower(username)=lower(?) OR lower(email)=lower(?)",
            (identifier, identifier)
        ).fetchone()

        if not user:
            log_event(identifier or "unknown", "LOGIN_FAIL", "FAILED", "Користувача не знайдено")
            flash("Невірний логін або пароль.", "danger")
            return render_template("login.html")

        if user["is_locked_by_admin"]:
            log_event(user["username"], "LOGIN_BLOCKED", "BLOCKED", "Акаунт заблоковано адміністратором", user["id"])
            flash("Обліковий запис заблоковано адміністратором.", "danger")
            return render_template("login.html")

        if user["locked_until"]:
            locked_dt = datetime.strptime(user["locked_until"], "%Y-%m-%d %H:%M:%S")
            if datetime.now() < locked_dt:
                log_event(user["username"], "LOGIN_LOCKED", "BLOCKED", f"Тимчасове блокування до {user['locked_until']}", user["id"])
                flash(f"Перевищено ліміт спроб входу. Акаунт заблоковано до {user['locked_until']}.", "danger")
                return render_template("login.html")
            else:
                db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
                db.commit()

        if not verify_password(password, user["password_hash"]):
            attempts = user["failed_attempts"] + 1
            if attempts >= MAX_FAILED_ATTEMPTS:
                lock_until = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
                db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", (attempts, lock_until, user["id"]))
                db.commit()
                log_event(user["username"], "BRUTEFORCE_LOCK", "BLOCKED", f"Блокування після {attempts} невдалих спроб (до {lock_until})", user["id"])
                flash(f"Перевищено ліміт невдалих спроб ({attempts}). Акаунт заблоковано до {lock_until}.", "danger")
            else:
                db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, user["id"]))
                db.commit()
                log_event(user["username"], "LOGIN_FAIL", "FAILED", f"Невірний пароль (спроба {attempts} з {MAX_FAILED_ATTEMPTS})", user["id"])
                flash(f"Невірний пароль (спроба {attempts} з {MAX_FAILED_ATTEMPTS}).", "warning")
            return render_template("login.html")

        db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        db.commit()

        if user["two_fa_enabled"]:
            session["pending_2fa_user_id"] = user["id"]
            if user["two_fa_method"] == "email":
                otp = f"{secrets.randbelow(1000000):06d}"
                exp_str = (datetime.now() + timedelta(minutes=OTP_TTL_MIN)).strftime("%Y-%m-%d %H:%M:%S")
                db.execute("UPDATE users SET email_otp_code = ?, email_otp_expires = ? WHERE id = ?", (otp, exp_str, user["id"]))
                db.commit()
                body = f"<p>Ваш одноразовий код для входу (2FA): <b>{otp}</b></p><p>Діє до: {exp_str}</p>"
                send_email(user["email"], f"Код 2FA: {otp}", body, None, "2FA OTP", exp_str)
                flash("Код 2FA надіслано на пошту.", "info")
            return redirect(url_for("verify_2fa"))

        session.clear()
        session["user_id"] = user["id"]
        log_event(user["username"], "LOGIN_SUCCESS", "SUCCESS", "Успішний вхід за паролем", user["id"])
        return redirect(url_for("profile"))

    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    uid = session.get("pending_2fa_user_id")
    if not uid:
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("otp_code", "").strip()
        ok = False
        if user["two_fa_method"] == "email":
            if user["email_otp_code"] and user["email_otp_expires"]:
                if datetime.now() <= datetime.strptime(user["email_otp_expires"], "%Y-%m-%d %H:%M:%S"):
                    if hmac.compare_digest(user["email_otp_code"], code):
                        ok = True
                        db.execute("UPDATE users SET email_otp_code = NULL, email_otp_expires = NULL WHERE id = ?", (user["id"],))
                        db.commit()
        else:
            ok = verify_totp(user["totp_secret"], code)

        if ok:
            session.clear()
            session["user_id"] = user["id"]
            log_event(user["username"], "2FA_SUCCESS", "SUCCESS", f"Успішний вхід з 2FA ({user['two_fa_method']})", user["id"])
            return redirect(url_for("profile"))
        else:
            log_event(user["username"], "2FA_FAIL", "FAILED", "Невірний код 2FA", user["id"])
            flash("Невірний або прострочений код 2FA.", "danger")

    demo_totp = get_totp_token(user["totp_secret"]) if user["totp_secret"] else ""
    return render_template("verify_2fa.html", user=user, current_totp_demo=demo_totp)


@app.route("/logout")
def logout():
    user = get_current_user()
    if user:
        log_event(user["username"], "LOGOUT", "SUCCESS", "Вихід із системи", user["id"])
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile")
@login_required
def profile():
    user = get_current_user()
    db = get_db()
    logs = db.execute("SELECT * FROM login_logs WHERE user_id = ? ORDER BY id DESC LIMIT 8", (user["id"],)).fetchall()
    totp_code = get_totp_token(user["totp_secret"]) if user["totp_secret"] else ""
    return render_template("profile.html", user=user, my_logs=logs, current_totp_code=totp_code)


@app.route("/profile/2fa", methods=["POST"])
@login_required
def update_2fa():
    user = get_current_user()
    action = request.form.get("action")
    method = request.form.get("two_fa_method", "totp")
    db = get_db()

    if action == "enable":
        db.execute("UPDATE users SET two_fa_enabled = 1, two_fa_method = ? WHERE id = ?", (method, user["id"]))
        db.commit()
        log_event(user["username"], "2FA_ENABLE", "SUCCESS", f"Увімкнено 2FA ({method})", user["id"])
        flash(f"Двофакторну автентифікацію ({method.upper()}) увімкнено.", "success")
    elif action == "disable":
        db.execute("UPDATE users SET two_fa_enabled = 0 WHERE id = ?", (user["id"],))
        db.commit()
        log_event(user["username"], "2FA_DISABLE", "SUCCESS", "Вимкнено 2FA", user["id"])
        flash("Двофакторну автентифікацію вимкнено.", "info")

    return redirect(url_for("profile"))


@app.route("/oauth/login/<provider>")
def oauth_login(provider):
    if provider not in ("google", "github"):
        return redirect(url_for("login"))
    state = secrets.token_urlsafe(16)
    session["oidc_state"] = state
    return redirect(url_for("oidc_authorize", provider=provider, state=state))


@app.route("/oauth/authorize/<provider>")
def oidc_authorize(provider):
    state = request.args.get("state", "")
    accounts = [
        {"name": "Денис (Студент)", "email": f"denis@{provider}.com", "sub": f"{provider}_101"},
        {"name": "Тестовий Користувач", "email": f"user@{provider}.com", "sub": f"{provider}_202"}
    ]
    return render_template("oidc_consent.html", provider=provider, state=state, demo_accounts=accounts)


@app.route("/oauth/callback/<provider>", methods=["POST"])
def oauth_callback(provider):
    state = request.form.get("state", "")
    if not state or state != session.get("oidc_state"):
        flash("Помилка перевірки state (OpenID Connect).", "danger")
        return redirect(url_for("login"))

    email = request.form.get("email", "").strip().lower()
    sub = request.form.get("sub", f"{provider}_{secrets.token_hex(4)}")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE lower(email)=lower(?)", (email,)).fetchone()

    if not user:
        base_name = re.sub(r"[^a-zA-Z0-9_]", "_", email.split("@")[0])
        username = base_name
        idx = 1
        while db.execute("SELECT id FROM users WHERE lower(username)=lower(?)", (username,)).fetchone():
            username = f"{base_name}_{idx}"
            idx += 1
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur = db.execute("""
            INSERT INTO users (
                username, email, password_hash, role, is_active,
                is_locked_by_admin, failed_attempts, two_fa_enabled,
                two_fa_method, totp_secret, oauth_provider, oauth_sub, created_at
            ) VALUES (?, ?, ?, 'user', 1, 0, 0, 0, 'totp', ?, ?, ?, ?)
        """, (username, email, hash_password(secrets.token_urlsafe(16) + "Aa1!"), generate_totp_secret(), provider.upper(), sub, now_str))
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
        log_event(user["username"], "OIDC_LOGIN", "SUCCESS", f"Реєстрація та вхід через {provider.upper()}", user["id"])
    else:
        if user["is_locked_by_admin"]:
            flash("Обліковий запис заблоковано адміністратором.", "danger")
            return redirect(url_for("login"))
        db.execute("UPDATE users SET oauth_provider=?, oauth_sub=?, is_active=1 WHERE id=?", (provider.upper(), sub, user["id"]))
        db.commit()
        log_event(user["username"], "OIDC_LOGIN", "SUCCESS", f"Вхід через {provider.upper()}", user["id"])

    session.pop("oidc_state", None)
    session["user_id"] = user["id"]
    flash(f"Ви увійшли через {provider.upper()} (OpenID Connect).", "success")
    return redirect(url_for("profile"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE lower(email)=lower(?)", (email,)).fetchone()
        if user:
            token, expires_str = create_token(user["id"], "password_reset", RESET_TTL_MIN)
            reset_url = url_for("reset_password", token=token, _external=True)
            body = (
                f"<p>Запит на відновлення пароля для <b>{user['username']}</b>.</p>"
                f"<p>Посилання для скидання пароля: <a href='{reset_url}'>{reset_url}</a></p>"
                f"<p>Одноразовий токен: <code>{token}</code> (діє до {expires_str}).</p>"
            )
            send_email(user["email"], "Відновлення пароля", body, reset_url, "Скидання пароля", expires_str)
            log_event(user["username"], "RESET_REQUEST", "SUCCESS", f"Надіслано токен відновлення (до {expires_str})", user["id"])
        flash("Якщо email зареєстровано, лист із посиланням для відновлення надіслано.", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    row = db.execute("SELECT * FROM security_tokens WHERE token=? AND token_type='password_reset'", (token,)).fetchone()
    if not row or row["used"] == 1:
        flash("Токен відновлення недійсний або вже використаний.", "danger")
        return redirect(url_for("login"))
    if datetime.now() > datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S"):
        flash("Термін дії токена минув.", "danger")
        return redirect(url_for("forgot_password"))

    user = db.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
    if request.method == "POST":
        pwd = request.form.get("password", "")
        conf = request.form.get("confirm_password", "")
        if pwd != conf:
            flash("Паролі не збігаються.", "danger")
            return render_template("reset_password.html", token=token, user=user, expires_at=row["expires_at"])

        ok, errs = validate_password_policy(pwd, user["username"])
        if not ok:
            for e in errs:
                flash(e, "danger")
            return render_template("reset_password.html", token=token, user=user, expires_at=row["expires_at"])

        db.execute("UPDATE security_tokens SET used=1 WHERE id=?", (row["id"],))
        db.execute("UPDATE users SET password_hash=?, failed_attempts=0, locked_until=NULL WHERE id=?", (hash_password(pwd), user["id"]))
        db.commit()
        log_event(user["username"], "RESET_SUCCESS", "SUCCESS", "Пароль змінено за токеном", user["id"])
        flash("Новий пароль встановлено. Увійдіть у систему.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token, user=user, expires_at=row["expires_at"])


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
    logs = db.execute("SELECT * FROM login_logs ORDER BY id DESC LIMIT 100").fetchall()
    stats = db.execute("""
        SELECT username_or_email,
               COUNT(*) AS total_events,
               SUM(CASE WHEN status IN ('FAILED','BLOCKED') THEN 1 ELSE 0 END) AS failed_cnt,
               SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS success_cnt
        FROM login_logs
        GROUP BY lower(username_or_email)
        ORDER BY total_events DESC
    """).fetchall()
    return render_template("admin.html", users=users, logs=logs, attempt_stats=stats)


@app.route("/admin/user/<int:target_id>/toggle-lock", methods=["POST"])
@admin_required
def admin_toggle_lock(target_id):
    current = get_current_user()
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
    if not target or target["id"] == current["id"]:
        return redirect(url_for("admin_dashboard"))

    if target["is_locked_by_admin"] or target["locked_until"]:
        db.execute("UPDATE users SET is_locked_by_admin=0, failed_attempts=0, locked_until=NULL WHERE id=?", (target_id,))
        db.commit()
        log_event(target["username"], "ADMIN_UNLOCK", "SUCCESS", f"Розблоковано адміністратором {current['username']}", target["id"])
        flash(f"Користувача {target['username']} розблоковано.", "success")
    else:
        db.execute("UPDATE users SET is_locked_by_admin=1 WHERE id=?", (target_id,))
        db.commit()
        log_event(target["username"], "ADMIN_LOCK", "BLOCKED", f"Заблоковано адміністратором {current['username']}", target["id"])
        flash(f"Користувача {target['username']} заблоковано.", "warning")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/<int:target_id>/toggle-role", methods=["POST"])
@admin_required
def admin_toggle_role(target_id):
    current = get_current_user()
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
    if target and target["id"] != current["id"]:
        new_role = "admin" if target["role"] == "user" else "user"
        db.execute("UPDATE users SET role=? WHERE id=?", (new_role, target_id))
        db.commit()
        log_event(target["username"], "ROLE_CHANGE", "SUCCESS", f"Змінено роль на {new_role}", target["id"])
    return redirect(url_for("admin_dashboard"))


@app.route("/mailbox")
def mailbox():
    db = get_db()
    db.execute("UPDATE sent_emails SET is_read = 1")
    db.commit()
    emails = db.execute("SELECT * FROM sent_emails ORDER BY id DESC").fetchall()
    return render_template("mailbox.html", emails=emails)


@app.route("/mailbox/clear", methods=["POST"])
def clear_mailbox():
    get_db().execute("DELETE FROM sent_emails")
    get_db().commit()
    return redirect(url_for("mailbox"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)

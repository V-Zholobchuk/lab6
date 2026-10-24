import re
import hmac
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, session, flash

from config import Config
from database import get_db, log_event
from services.security import (
    hash_password, verify_password, validate_password_policy,
    generate_totp_secret, verify_totp, generate_captcha_svg
)
from services.mailer import send_real_email, create_token

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/captcha/refresh")
def refresh_captcha():
    code, svg_uri = generate_captcha_svg()
    session["captcha_code"] = code
    return {"svg_uri": svg_uri}


@auth_bp.route("/register", methods=["GET", "POST"])
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

        token, expires_str = create_token(user_id, "activation", Config.ACTIVATION_TTL_MIN)
        act_url = url_for("auth.activate_account", token=token, _external=True)

        body = (
            f"<h3>Підтвердження реєстрації</h3>"
            f"<p>Вітаємо, <b>{username}</b>!</p>"
            f"<p>Для активації облікового запису перейдіть за посиланням:</p>"
            f"<p><a href='{act_url}'>{act_url}</a></p>"
            f"<p><small>Одноразовий токен дійсний до: {expires_str}</small></p>"
        )
        ok_mail, err_mail = send_real_email(email, "Активація облікового запису", body)
        log_event(username, "REGISTER", "SUCCESS", f"Реєстрація ({email}), SMTP={ok_mail}", user_id)

        if ok_mail:
            flash(f"Реєстрація успішна! Лист для активації надіслано на {email}.", "success")
        else:
            flash(f"Акаунт створено, але не вдалося надіслати email ({err_mail}). Перевірте SMTP у .env.", "warning")
        return redirect(url_for("auth.login"))

    code, svg_uri = generate_captcha_svg()
    session["captcha_code"] = code
    return render_template("register.html", captcha_svg=svg_uri, form_data={})


@auth_bp.route("/activate/<token>")
def activate_account(token):
    db = get_db()
    row = db.execute("SELECT * FROM security_tokens WHERE token = ? AND token_type = 'activation'", (token,)).fetchone()
    if not row:
        flash("Недійсний токен активації.", "danger")
        return redirect(url_for("auth.login"))
    if row["used"] == 1:
        flash("Токен вже використано.", "warning")
        return redirect(url_for("auth.login"))
    if datetime.now() > datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S"):
        flash("Термін дії токена минув.", "danger")
        return redirect(url_for("auth.login"))

    db.execute("UPDATE security_tokens SET used = 1 WHERE id = ?", (row["id"],))
    db.execute("UPDATE users SET is_active = 1 WHERE id = ?", (row["user_id"],))
    db.commit()

    user = db.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
    log_event(user["username"], "ACTIVATE", "SUCCESS", "Акаунт активовано за токеном з пошти", user["id"])
    flash("Обліковий запис успішно активовано!", "success")
    return redirect(url_for("profile.view_profile") if session.get("user_id") else url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
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
            if attempts >= Config.MAX_FAILED_ATTEMPTS:
                lock_until = (datetime.now() + timedelta(minutes=Config.LOCKOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
                db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", (attempts, lock_until, user["id"]))
                db.commit()
                log_event(user["username"], "BRUTEFORCE_LOCK", "BLOCKED", f"Блокування після {attempts} невдалих спроб (до {lock_until})", user["id"])
                flash(f"Перевищено ліміт невдалих спроб ({attempts}). Акаунт заблоковано до {lock_until}.", "danger")
            else:
                db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, user["id"]))
                db.commit()
                log_event(user["username"], "LOGIN_FAIL", "FAILED", f"Невірний пароль (спроба {attempts} з {Config.MAX_FAILED_ATTEMPTS})", user["id"])
                flash(f"Невірний пароль (спроба {attempts} з {Config.MAX_FAILED_ATTEMPTS}).", "warning")
            return render_template("login.html")

        db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        db.commit()

        if user["two_fa_enabled"]:
            session["pending_2fa_user_id"] = user["id"]
            if user["two_fa_method"] == "email":
                otp = f"{secrets.randbelow(1000000):06d}"
                exp_str = (datetime.now() + timedelta(minutes=Config.OTP_TTL_MIN)).strftime("%Y-%m-%d %H:%M:%S")
                db.execute("UPDATE users SET email_otp_code = ?, email_otp_expires = ? WHERE id = ?", (otp, exp_str, user["id"]))
                db.commit()
                body = (
                    f"<h3>Двофакторна автентифікація (2FA)</h3>"
                    f"<p>Ваш одноразовий код для входу в систему: <b style='font-size:20px;'>{otp}</b></p>"
                    f"<p><small>Код дійсний до: {exp_str}</small></p>"
                )
                ok_mail, err_mail = send_real_email(user["email"], f"Код підтвердження входу: {otp}", body)
                if ok_mail:
                    flash(f"Одноразовий код 2FA надіслано на пошту {user['email']}.", "info")
                else:
                    flash(f"Помилка відправки коду на пошту: {err_mail}", "danger")
            return redirect(url_for("auth.verify_2fa"))

        session.clear()
        session["user_id"] = user["id"]
        log_event(user["username"], "LOGIN_SUCCESS", "SUCCESS", "Успішний вхід за паролем", user["id"])
        return redirect(url_for("profile.view_profile"))

    return render_template("login.html")


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    uid = session.get("pending_2fa_user_id")
    if not uid:
        return redirect(url_for("auth.login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not user:
        return redirect(url_for("auth.login"))

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
            return redirect(url_for("profile.view_profile"))
        else:
            log_event(user["username"], "2FA_FAIL", "FAILED", "Невірний код 2FA", user["id"])
            flash("Невірний або прострочений код 2FA.", "danger")

    return render_template("verify_2fa.html", user=user)


@auth_bp.route("/logout")
def logout():
    uid = session.get("user_id")
    if uid:
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if user:
            log_event(user["username"], "LOGOUT", "SUCCESS", "Вихід із системи", user["id"])
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE lower(email)=lower(?)", (email,)).fetchone()
        if user:
            token, expires_str = create_token(user["id"], "password_reset", Config.RESET_TTL_MIN)
            reset_url = url_for("auth.reset_password", token=token, _external=True)
            body = (
                f"<h3>Відновлення пароля</h3>"
                f"<p>Запит на скидання пароля для облікового запису <b>{user['username']}</b>.</p>"
                f"<p>Для встановлення нового пароля перейдіть за посиланням:</p>"
                f"<p><a href='{reset_url}'>{reset_url}</a></p>"
                f"<p><small>Одноразовий токен дійсний до: {expires_str} ({Config.RESET_TTL_MIN} хв)</small></p>"
            )
            ok_mail, err_mail = send_real_email(user["email"], "Відновлення пароля", body)
            log_event(user["username"], "RESET_REQUEST", "SUCCESS", f"Надіслано токен відновлення (SMTP={ok_mail})", user["id"])
            if not ok_mail:
                flash(f"Помилка відправки листа: {err_mail}", "danger")
                return redirect(url_for("auth.forgot_password"))

        flash(f"Лист із посиланням для відновлення пароля надіслано на {email}.", "info")
        return redirect(url_for("auth.login"))
    return render_template("forgot_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    row = db.execute("SELECT * FROM security_tokens WHERE token=? AND token_type='password_reset'", (token,)).fetchone()
    if not row or row["used"] == 1:
        flash("Токен відновлення недійсний або вже використаний.", "danger")
        return redirect(url_for("auth.login"))
    if datetime.now() > datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S"):
        flash("Термін дії токена минув.", "danger")
        return redirect(url_for("auth.forgot_password"))

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
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", token=token, user=user, expires_at=row["expires_at"])

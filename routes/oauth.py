import re
import secrets
import requests
from datetime import datetime
from urllib.parse import urlencode
from flask import Blueprint, request, redirect, url_for, session, flash

from config import Config
from database import get_db, log_event
from services.security import hash_password, generate_totp_secret

oauth_bp = Blueprint("oauth", __name__, url_prefix="/oauth")


@oauth_bp.route("/login/<provider>")
def oauth_login(provider):
    state = secrets.token_urlsafe(16)
    session["oidc_state"] = state
    redirect_uri = url_for("oauth.oauth_callback", provider=provider, _external=True)

    if provider == "google":
        if not Config.GOOGLE_CLIENT_ID:
            flash("Не задано GOOGLE_CLIENT_ID у файлі .env.", "danger")
            return redirect(url_for("auth.login"))
        params = {
            "client_id": Config.GOOGLE_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "online",
            "prompt": "select_account"
        }
        return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}")

    elif provider == "github":
        if not Config.GITHUB_CLIENT_ID:
            flash("Не задано GITHUB_CLIENT_ID у файлі .env.", "danger")
            return redirect(url_for("auth.login"))
        params = {
            "client_id": Config.GITHUB_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "scope": "read:user user:email",
            "state": state
        }
        return redirect(f"https://github.com/login/oauth/authorize?{urlencode(params)}")

    return redirect(url_for("auth.login"))


@oauth_bp.route("/callback/<provider>")
def oauth_callback(provider):
    state = request.args.get("state", "")
    code = request.args.get("code", "")
    error = request.args.get("error", "")

    if error:
        flash(f"Відмова авторизації OAuth: {error}", "danger")
        return redirect(url_for("auth.login"))

    if not state or state != session.get("oidc_state"):
        flash("Помилка безпеки OAuth/OIDC: невірний параметр state.", "danger")
        return redirect(url_for("auth.login"))

    redirect_uri = url_for("oauth.oauth_callback", provider=provider, _external=True)
    email = None
    sub = None

    try:
        if provider == "google":
            token_res = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": Config.GOOGLE_CLIENT_ID,
                    "client_secret": Config.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code"
                },
                timeout=10
            ).json()

            access_token = token_res.get("access_token")
            if not access_token:
                flash(f"Помилка отримання токена Google: {token_res.get('error_description', token_res)}", "danger")
                return redirect(url_for("auth.login"))

            userinfo = requests.get(
                "https://openidconnect.googleapis.com/v1/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10
            ).json()

            email = userinfo.get("email")
            sub = str(userinfo.get("sub"))

        elif provider == "github":
            token_res = requests.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": Config.GITHUB_CLIENT_ID,
                    "client_secret": Config.GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": redirect_uri
                },
                timeout=10
            ).json()

            access_token = token_res.get("access_token")
            if not access_token:
                flash(f"Помилка отримання токена GitHub: {token_res}", "danger")
                return redirect(url_for("auth.login"))

            headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
            user_data = requests.get("https://api.github.com/user", headers=headers, timeout=10).json()
            sub = str(user_data.get("id"))
            email = user_data.get("email")

            if not email:
                emails_list = requests.get("https://api.github.com/user/emails", headers=headers, timeout=10).json()
                if isinstance(emails_list, list):
                    for item in emails_list:
                        if item.get("primary") and item.get("verified"):
                            email = item.get("email")
                            break
                    if not email and emails_list:
                        email = emails_list[0].get("email")
    except Exception as e:
        flash(f"Помилка з'єднання з OAuth-провайдером: {e}", "danger")
        return redirect(url_for("auth.login"))

    if not email:
        flash("Не вдалося отримати email від зовнішнього провайдера.", "danger")
        return redirect(url_for("auth.login"))

    email = email.strip().lower()
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
            return redirect(url_for("auth.login"))
        db.execute("UPDATE users SET oauth_provider=?, oauth_sub=?, is_active=1 WHERE id=?", (provider.upper(), sub, user["id"]))
        db.commit()
        log_event(user["username"], "OIDC_LOGIN", "SUCCESS", f"Вхід через {provider.upper()}", user["id"])

    session.pop("oidc_state", None)
    session["user_id"] = user["id"]
    flash(f"Ви успішно увійшли через {provider.upper()} ({email}).", "success")
    return redirect(url_for("profile.view_profile"))

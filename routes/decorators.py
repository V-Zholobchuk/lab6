from functools import wraps
from flask import session, flash, redirect, url_for
from database import get_db, log_event


def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Увійдіть у систему.", "warning")
            return redirect(url_for("auth.login"))
        if user["is_locked_by_admin"]:
            session.clear()
            flash("Обліковий запис заблоковано адміністратором.", "danger")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("auth.login"))
        if user["role"] != "admin":
            log_event(user["username"], "RBAC_DENIED", "DENIED", "Спроба доступу до адмін-панелі", user["id"])
            flash("Доступ дозволено лише адміністратору.", "danger")
            return redirect(url_for("profile.view_profile"))
        return f(*args, **kwargs)
    return wrapper

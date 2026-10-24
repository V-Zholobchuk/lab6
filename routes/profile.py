from flask import Blueprint, render_template, request, redirect, url_for, flash

from config import Config
from database import get_db, log_event
from routes.decorators import login_required, get_current_user
from services.security import generate_qr_svg_data_uri
from services.mailer import send_real_email, create_token

profile_bp = Blueprint("profile", __name__)


@profile_bp.route("/profile")
@login_required
def view_profile():
    user = get_current_user()
    db = get_db()
    logs = db.execute("SELECT * FROM login_logs WHERE user_id = ? ORDER BY id DESC LIMIT 8", (user["id"],)).fetchall()
    otpauth_uri = f"otpauth://totp/AuthSystem:{user['username']}?secret={user['totp_secret']}&issuer=AuthSystem"
    qr_svg_uri = generate_qr_svg_data_uri(otpauth_uri)
    return render_template("profile.html", user=user, my_logs=logs, qr_svg_uri=qr_svg_uri)


@profile_bp.route("/profile/2fa", methods=["POST"])
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

    return redirect(url_for("profile.view_profile"))


@profile_bp.route("/resend-activation", methods=["POST"])
@login_required
def resend_activation():
    user = get_current_user()
    if not user["is_active"]:
        token, expires_str = create_token(user["id"], "activation", Config.ACTIVATION_TTL_MIN)
        act_url = url_for("auth.activate_account", token=token, _external=True)
        body = (
            f"<h3>Активація облікового запису</h3>"
            f"<p>Перейдіть за посиланням для активації акаунта <b>{user['username']}</b>:</p>"
            f"<p><a href='{act_url}'>{act_url}</a></p>"
            f"<p><small>Діє до: {expires_str}</small></p>"
        )
        ok_mail, err_mail = send_real_email(user["email"], "Повторне посилання для активації", body)
        if ok_mail:
            flash(f"Лист із посиланням для активації надіслано на {user['email']}.", "success")
        else:
            flash(f"Помилка відправки пошти: {err_mail}", "danger")
    return redirect(url_for("profile.view_profile"))

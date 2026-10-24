from flask import Blueprint, render_template, redirect, url_for, flash
from database import get_db, log_event
from routes.decorators import admin_required, get_current_user

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("")
@admin_required
def dashboard():
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


@admin_bp.route("/user/<int:target_id>/toggle-lock", methods=["POST"])
@admin_required
def toggle_lock(target_id):
    current = get_current_user()
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
    if not target or target["id"] == current["id"]:
        return redirect(url_for("admin.dashboard"))

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
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/user/<int:target_id>/toggle-role", methods=["POST"])
@admin_required
def toggle_role(target_id):
    current = get_current_user()
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
    if target and target["id"] != current["id"]:
        new_role = "admin" if target["role"] == "user" else "user"
        db.execute("UPDATE users SET role=? WHERE id=?", (new_role, target_id))
        db.commit()
        log_event(target["username"], "ROLE_CHANGE", "SUCCESS", f"Змінено роль на {new_role}", target["id"])
    return redirect(url_for("admin.dashboard"))

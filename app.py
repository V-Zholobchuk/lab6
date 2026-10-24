from flask import Flask, redirect, url_for
from config import Config
from database import init_db, close_db
from routes.decorators import get_current_user
from routes.auth import auth_bp
from routes.oauth import oauth_bp
from routes.profile import profile_bp
from routes.admin import admin_bp

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

app.teardown_appcontext(close_db)

app.register_blueprint(auth_bp)
app.register_blueprint(oauth_bp)
app.register_blueprint(profile_bp)
app.register_blueprint(admin_bp)


@app.context_processor
def inject_globals():
    return dict(current_user=get_current_user())


@app.route("/")
def index():
    return redirect(url_for("profile.view_profile") if get_current_user() else url_for("auth.login"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)

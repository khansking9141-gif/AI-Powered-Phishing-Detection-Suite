from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail

from config import Config
from database.db import get_db_connection

from routes.auth import auth
from routes.dashboard import dashboard_routes
from routes.url import url_routes
from routes.history import history_routes
from routes.qr import qr_routes
from routes.email import email_routes
from routes.admin import admin_routes


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

# LOAD ENVIRONMENT CONFIGURATION
app.config.from_object(Config)

# CHECK SECRET KEY
if not app.config.get("SECRET_KEY"):
    raise RuntimeError(
        "SECRET_KEY is missing. Please configure it in your .env file."
    )

# APPLICATION SETTINGS
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False


# =========================================================
# FLASK-MAIL CONFIGURATION
# =========================================================

mail = Mail(app)


# =========================================================
# CSRF PROTECTION
# =========================================================

csrf = CSRFProtect(app)


# =========================================================
# FILE UPLOAD ERROR
# =========================================================

@app.errorhandler(413)
def request_entity_too_large(error):

    return (
        "File too large. Please upload an image smaller than 5 MB.",
        413
    )


# =========================================================
# SECURITY HEADERS
# =========================================================

@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "SAMEORIGIN"

    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    return response


# =========================================================
# FLASK LOGIN
# =========================================================

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "auth.login"


# =========================================================
# LOAD LOGGED-IN USER
# =========================================================

@login_manager.user_loader
def load_user(user_id):

    connection = get_db_connection()

    if not connection:
        return None

    cursor = connection.cursor(dictionary=True)

    try:

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

    finally:

        cursor.close()
        connection.close()

    if user:

        from routes.auth import User

        return User(
            user["id"],
            user["username"],
            user["email"],
            user["role"]
        )

    return None


# =========================================================
# REGISTER BLUEPRINTS
# =========================================================

app.register_blueprint(auth)

app.register_blueprint(dashboard_routes)

app.register_blueprint(url_routes)

app.register_blueprint(history_routes)

app.register_blueprint(qr_routes)

app.register_blueprint(email_routes)

app.register_blueprint(admin_routes)


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return "AI-Powered Phishing Detection Suite is running!"


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(debug=True)
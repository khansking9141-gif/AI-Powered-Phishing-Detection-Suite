import secrets

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app
)

from flask_login import (
    UserMixin,
    login_user,
    logout_user,
    login_required
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired
)

from flask_mail import Message

from database.db import get_db_connection


auth = Blueprint("auth", __name__)


# =========================================================
# PUBLIC HOME / LANDING PAGE
# =========================================================

@auth.route("/")
def home():

    return render_template("home.html")


# =========================================================
# USER CLASS
# =========================================================

class User(UserMixin):

    def __init__(self, id, username, email, role):

        self.id = id
        self.username = username
        self.email = email
        self.role = role


# =========================================================
# REGISTER
# =========================================================

@auth.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # CHECK GMAIL ADDRESS

        if (
            "@" not in email
            or email.lower().count("@") != 1
            or not email.lower().endswith("@gmail.com")
        ):

            return render_template(
                "register.html",
                error="Please use a valid Gmail address ending with @gmail.com."
            )

        # CHECK PASSWORD LENGTH

        if len(password) < 6:

            return render_template(
                "register.html",
                error="Password must be at least 6 characters long."
            )

        # CHECK PASSWORD MATCH

        if password != confirm_password:

            return render_template(
                "register.html",
                error="Passwords do not match. Please try again."
            )

        # CHECK DUPLICATE EMAIL

        connection = None
        cursor = None

        try:

            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT id
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            existing_user = cursor.fetchone()

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

        if existing_user:

            return render_template(
                "register.html",
                error=(
                    "An account with this email already exists. "
                    "Please use another email or sign in."
                )
            )

        # CREATE PASSWORD HASH

        password_hash = generate_password_hash(password)

        connection = None
        cursor = None

        try:

            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO users
                (
                    username,
                    email,
                    password_hash
                )
                VALUES (%s, %s, %s)
                """,
                (
                    username,
                    email,
                    password_hash
                )
            )

            connection.commit()

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

        flash(
            "Account created successfully! You can now sign in to PhishGuard.",
            "success"
        )

        return redirect(url_for("auth.login"))

    return render_template("register.html")


# =========================================================
# LOGIN
# =========================================================

@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        connection = None
        cursor = None

        try:

            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT *
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            user = cursor.fetchone()

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

        # CHECK CREDENTIALS

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            # CHECK ACCOUNT STATUS

            if not bool(user["is_active"]):

                return render_template(
                    "login.html",
                    error=(
                        "Your account has been deactivated. "
                        "Please contact the administrator."
                    )
                )

            # CREATE LOGGED-IN USER

            logged_in_user = User(
                user["id"],
                user["username"],
                user["email"],
                user["role"]
            )

            login_user(logged_in_user)

            # ADMIN DASHBOARD

            if user["role"].lower() == "admin":

                return redirect(
                    url_for("admin_routes.admin_dashboard")
                )

            # USER DASHBOARD

            return redirect(
                url_for("auth.dashboard")
            )

        return render_template(
            "login.html",
            error=(
                "Invalid email or password. "
                "Please check your credentials and try again."
            )
        )

    return render_template("login.html")


# =========================================================
# CONTACT ADMIN
# =========================================================

@auth.route("/contact-admin", methods=["GET", "POST"])
def contact_admin():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        subject = request.form.get(
            "subject", ""
        ).strip()

        message = request.form.get(
            "message", ""
        ).strip()

        # VALIDATE INPUT

        if not email or not subject or not message:

            return render_template(
                "contact_admin.html",
                error="Please fill in all fields."
            )

        if len(email) > 255 or "@" not in email:

            return render_template(
                "contact_admin.html",
                error="Please enter a valid email address."
            )

        if len(subject) > 255:

            return render_template(
                "contact_admin.html",
                error="Subject must not exceed 255 characters."
            )

        if len(message) > 5000:

            return render_template(
                "contact_admin.html",
                error="Message must not exceed 5000 characters."
            )

        # GENERATE TRACKING CODE

        tracking_token = secrets.token_urlsafe(32)

        connection = None
        cursor = None

        try:

            connection = get_db_connection()

            cursor = connection.cursor(dictionary=True)

            # FIND REGISTERED USER, IF AVAILABLE

            cursor.execute(
                """
                SELECT id
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            user = cursor.fetchone()

            user_id = user["id"] if user else None

            # SAVE REQUEST

            cursor.execute(
                """
                INSERT INTO user_requests
                (
                    user_id,
                    email,
                    subject,
                    message,
                    tracking_token
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    user_id,
                    email,
                    subject,
                    message,
                    tracking_token
                )
            )

            connection.commit()

        except Exception:

            if connection:
                connection.rollback()

            current_app.logger.exception(
                "Failed to save Contact Admin request."
            )

            return render_template(
                "contact_admin.html",
                error=(
                    "We could not submit your request right now. "
                    "Please try again later."
                )
            )

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

        # DISPLAY SUCCESS AND TRACKING CODE

        return render_template(
            "contact_admin.html",
            success=(
                "Your request has been submitted successfully. "
                "Save your tracking code to check its status later."
            ),
            tracking_token=tracking_token
        )

    return render_template("contact_admin.html")


# =========================================================
# CHECK REQUEST STATUS
# =========================================================

@auth.route("/request-status", methods=["GET", "POST"])
def request_status():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        tracking_token = request.form.get(
            "tracking_token", ""
        ).strip()

        # VALIDATE INPUT

        if not email or not tracking_token:

            return render_template(
                "request_status.html",
                error="Please enter both your email address and tracking code."
            )

        connection = None
        cursor = None

        try:

            connection = get_db_connection()

            cursor = connection.cursor(dictionary=True)

            # VERIFY EMAIL AND TRACKING CODE TOGETHER

            cursor.execute(
                """
                SELECT
                    subject,
                    status,
                    admin_response,
                    created_at,
                    updated_at
                FROM user_requests
                WHERE tracking_token = %s
                AND LOWER(email) = %s
                LIMIT 1
                """,
                (
                    tracking_token,
                    email
                )
            )

            request_record = cursor.fetchone()

        except Exception:

            current_app.logger.exception(
                "Failed to check request status."
            )

            return render_template(
                "request_status.html",
                error=(
                    "Unable to check your request status right now. "
                    "Please try again later."
                )
            )

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

        # REQUEST NOT FOUND

        if not request_record:

            return render_template(
                "request_status.html",
                error=(
                    "No matching request was found. "
                    "Please check your email address and tracking code."
                )
            )

        # DISPLAY REQUEST DETAILS

        return render_template(
            "request_status.html",
            request_record=request_record
        )

    return render_template("request_status.html")


# =========================================================
# FORGOT PASSWORD
# =========================================================

@auth.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip()

        # GENERIC RESPONSE:
        # DO NOT REVEAL WHETHER THE ACCOUNT EXISTS.

        generic_message = (
            "If an account exists with that email address, "
            "a password reset link will be sent shortly. "
            "Please check your inbox."
        )

        connection = None
        cursor = None

        try:

            connection = get_db_connection()

            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT id, email, password_hash
                FROM users
                WHERE email = %s
                LIMIT 1
                """,
                (email,)
            )

            user = cursor.fetchone()

        except Exception:

            current_app.logger.exception(
                "Password reset account lookup failed."
            )

            return render_template(
                "forgot_password.html",
                success=generic_message
            )

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

        # SEND EMAIL ONLY IF ACCOUNT EXISTS

        if user:

            try:

                # CREATE RESET TOKEN

                serializer = URLSafeTimedSerializer(
                    current_app.config["SECRET_KEY"]
                )

                # INCLUDING THE CURRENT PASSWORD HASH MAKES
                # THE TOKEN INVALID AFTER A PASSWORD CHANGE.

                token_data = {
                    "email": user["email"],
                    "password_hash": user["password_hash"]
                }

                token = serializer.dumps(
                    token_data,
                    salt="password-reset-salt"
                )

                # CREATE RESET LINK

                reset_link = url_for(
                    "auth.reset_password",
                    token=token,
                    _external=True
                )

                # IMPORT MAIL AT RUNTIME TO AVOID
                # A CIRCULAR IMPORT WITH app.py.

                from app import mail

                # CREATE EMAIL

                message = Message(
                    subject="PhishGuard - Password Reset",
                    recipients=[user["email"]],
                    body=(
                        "Hello,\n\n"
                        "We received a request to reset your "
                        "PhishGuard account password.\n\n"
                        "Click the link below to create a new password:\n\n"
                        f"{reset_link}\n\n"
                        "This link is valid for 30 minutes and can "
                        "only be used once.\n\n"
                        "If you did not request a password reset, "
                        "you can safely ignore this email.\n\n"
                        "Regards,\n"
                        "PhishGuard Security Team"
                    )
                )

                # SEND EMAIL

                mail.send(message)

            except Exception:

                current_app.logger.exception(
                    "Password reset email could not be sent."
                )

        # SAME RESPONSE WHETHER ACCOUNT EXISTS OR NOT

        return render_template(
            "forgot_password.html",
            success=generic_message
        )

    return render_template("forgot_password.html")


# =========================================================
# RESET PASSWORD
# =========================================================

@auth.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    # CREATE TOKEN SERIALIZER

    serializer = URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"]
    )

    # VERIFY TOKEN AND EXPIRY

    try:

        token_data = serializer.loads(
            token,
            salt="password-reset-salt",
            max_age=1800
        )

    except SignatureExpired:

        return render_template(
            "reset_password.html",
            error=(
                "This password reset link has expired. "
                "Please request a new reset link."
            )
        )

    except (BadSignature, TypeError, ValueError):

        return render_template(
            "reset_password.html",
            error=(
                "This password reset link is invalid. "
                "Please request a new reset link."
            )
        )

    # CHECK TOKEN DATA

    if (
        not isinstance(token_data, dict)
        or not token_data.get("email")
        or not token_data.get("password_hash")
    ):

        return render_template(
            "reset_password.html",
            error="Invalid password reset link. Please request a new one."
        )

    email = token_data["email"]

    original_password_hash = token_data["password_hash"]

    # CHECK WHETHER TOKEN HAS ALREADY BEEN USED

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT password_hash
            FROM users
            WHERE email = %s
            LIMIT 1
            """,
            (email,)
        )

        user = cursor.fetchone()

    except Exception:

        current_app.logger.exception(
            "Password reset verification failed."
        )

        return render_template(
            "reset_password.html",
            error=(
                "Unable to verify this reset link right now. "
                "Please try again later."
            )
        )

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()

    # ACCOUNT MUST EXIST AND PASSWORD HASH MUST MATCH

    if (
        not user
        or user["password_hash"] != original_password_hash
    ):

        return render_template(
            "reset_password.html",
            error=(
                "This password reset link is invalid or has already "
                "been used. Please request a new reset link."
            )
        )

    # HANDLE NEW PASSWORD

    if request.method == "POST":

        password = request.form.get("password", "")

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        # CHECK PASSWORD LENGTH

        if len(password) < 6:

            return render_template(
                "reset_password.html",
                error="Password must be at least 6 characters long."
            )

        # CHECK PASSWORD MATCH

        if password != confirm_password:

            return render_template(
                "reset_password.html",
                error="Passwords do not match. Please try again."
            )

        # CREATE NEW PASSWORD HASH

        password_hash = generate_password_hash(password)

        connection = None
        cursor = None

        try:

            connection = get_db_connection()

            cursor = connection.cursor()

            # UPDATE ONLY IF THE ORIGINAL PASSWORD HASH
            # HAS NOT CHANGED SINCE THE TOKEN WAS CREATED.

            cursor.execute(
                """
                UPDATE users
                SET password_hash = %s
                WHERE email = %s
                AND password_hash = %s
                """,
                (
                    password_hash,
                    email,
                    original_password_hash
                )
            )

            connection.commit()

            if cursor.rowcount != 1:

                return render_template(
                    "reset_password.html",
                    error=(
                        "This password reset link has already been "
                        "used. Please request a new reset link."
                    )
                )

        except Exception:

            if connection:
                connection.rollback()

            current_app.logger.exception(
                "Password reset update failed."
            )

            return render_template(
                "reset_password.html",
                error=(
                    "Your password could not be updated right now. "
                    "Please try again later."
                )
            )

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

        flash(
            "Your password has been reset successfully. "
            "You can now sign in with your new password.",
            "success"
        )

        return redirect(url_for("auth.login"))

    return render_template("reset_password.html")


# =========================================================
# USER DASHBOARD
# =========================================================

@auth.route("/dashboard")
@login_required
def dashboard():

    return render_template("dashboard.html")


# =========================================================
# LOGOUT
# =========================================================

@auth.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("auth.login"))

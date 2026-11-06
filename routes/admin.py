from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request
)

from flask_login import (
    login_required,
    current_user
)

from database.db import get_db_connection


admin_routes = Blueprint(
    "admin_routes",
    __name__
)


# ==================================================
# ADMIN ACCESS CHECK
# ==================================================

def is_admin():

    return (
        current_user.is_authenticated
        and current_user.role == "admin"
    )


# ==================================================
# ADMIN DASHBOARD
# ==================================================

@admin_routes.route("/admin-dashboard")
@login_required
def admin_dashboard():

    if not is_admin():
        return "Access Denied", 403

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Total users
    cursor.execute("""
        SELECT COUNT(*) AS total_users
        FROM users
    """)

    total_users = cursor.fetchone()["total_users"]

    # Total scans
    cursor.execute("""
        SELECT COUNT(*) AS total_scans
        FROM scans
    """)

    total_scans = cursor.fetchone()["total_scans"]

    # URL scans
    cursor.execute("""
        SELECT COUNT(*) AS total_url
        FROM scans
        WHERE scan_type = 'URL'
    """)

    total_url = cursor.fetchone()["total_url"]

    # QR scans
    cursor.execute("""
        SELECT COUNT(*) AS total_qr
        FROM scans
        WHERE scan_type = 'QR'
    """)

    total_qr = cursor.fetchone()["total_qr"]

    # Email scans
    cursor.execute("""
        SELECT COUNT(*) AS total_email
        FROM scans
        WHERE scan_type = 'EMAIL'
    """)

    total_email = cursor.fetchone()["total_email"]

    # Phishing detections
    cursor.execute("""
        SELECT COUNT(*) AS phishing_count
        FROM scans
        WHERE LOWER(risk_level) = 'phishing'
    """)

    phishing_count = cursor.fetchone()["phishing_count"]

    # Safe scans
    cursor.execute("""
        SELECT COUNT(*) AS safe_count
        FROM scans
        WHERE LOWER(risk_level) = 'safe'
    """)

    safe_count = cursor.fetchone()["safe_count"]

    # Average risk score
    cursor.execute("""
        SELECT
            COALESCE(AVG(risk_score), 0) AS average_score
        FROM scans
    """)

    average_score = round(
        float(cursor.fetchone()["average_score"]),
        2
    )

    # Recent scan activity
    cursor.execute("""
        SELECT
            scans.*,
            users.username
        FROM scans
        LEFT JOIN users
            ON scans.user_id = users.id
        ORDER BY scans.created_at DESC
        LIMIT 10
    """)

    recent_scans = cursor.fetchall()

    # All platform users
    cursor.execute("""
        SELECT
            id,
            username,
            email,
            role,
            created_at,
            is_active
        FROM users
        ORDER BY id DESC
    """)

    users = cursor.fetchall()

    # Contact Admin requests
    cursor.execute("""
        SELECT
            user_requests.*,
            users.username
        FROM user_requests
        LEFT JOIN users
            ON user_requests.user_id = users.id
        ORDER BY
            CASE
                WHEN user_requests.status = 'Pending'
                THEN 0
                ELSE 1
            END,
            user_requests.created_at DESC
    """)

    user_requests = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_dashboard.html",

        total_users=total_users,
        total_scans=total_scans,

        total_url=total_url,
        total_qr=total_qr,
        total_email=total_email,

        phishing_count=phishing_count,
        safe_count=safe_count,

        average_score=average_score,

        recent_scans=recent_scans,

        users=users,

        user_requests=user_requests
    )


# ==================================================
# VIEW USER DETAILS
# ==================================================

@admin_routes.route("/admin/user/<int:user_id>")
@login_required
def view_user(user_id):

    if not is_admin():
        return "Access Denied", 403

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Get user details
    cursor.execute("""
        SELECT
            id,
            username,
            email,
            role,
            created_at,
            is_active
        FROM users
        WHERE id = %s
    """, (user_id,))

    user = cursor.fetchone()

    cursor.close()
    connection.close()

    if not user:
        flash("User not found.", "error")

        return redirect(
            url_for("admin_routes.admin_dashboard")
        )

    # IMPORTANT:
    # Keep the original working template name.
    return render_template(
        "view_user.html",
        user=user
    )


# ==================================================
# VIEW A SPECIFIC USER'S SCANS
# ==================================================

@admin_routes.route(
    "/admin/user/<int:user_id>/scans"
)
@login_required
def view_user_scans(user_id):

    if not is_admin():
        return "Access Denied", 403

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Get user details
    cursor.execute("""
        SELECT
            id,
            username,
            email,
            role,
            created_at,
            is_active
        FROM users
        WHERE id = %s
    """, (user_id,))

    user = cursor.fetchone()

    if not user:

        cursor.close()
        connection.close()

        flash("User not found.", "error")

        return redirect(
            url_for("admin_routes.admin_dashboard")
        )

    # Get user's scans
    cursor.execute("""
        SELECT
            id,
            scan_type,
            input_data,
            risk_score,
            risk_level,
            created_at
        FROM scans
        WHERE user_id = %s
        ORDER BY id DESC
    """, (user_id,))

    scans = cursor.fetchall()

    # Get user scan statistics
    cursor.execute("""
        SELECT

            COUNT(*) AS total_scans,

            COALESCE(
                SUM(
                    CASE
                        WHEN scan_type = 'URL'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS total_url,

            COALESCE(
                SUM(
                    CASE
                        WHEN scan_type = 'QR'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS total_qr,

            COALESCE(
                SUM(
                    CASE
                        WHEN scan_type = 'EMAIL'
                        THEN 1
                        ELSE 0
                    END
                ),
                0
            ) AS total_email

        FROM scans

        WHERE user_id = %s

    """, (user_id,))

    user_stats = cursor.fetchone()

    cursor.close()
    connection.close()

    # IMPORTANT:
    # Keep the original working template name.
    return render_template(
        "admin_user_scans.html",
        user=user,
        scans=scans,
        user_stats=user_stats
    )


# ==================================================
# CHANGE USER ROLE
# ==================================================

@admin_routes.route(
    "/admin/user/<int:user_id>/toggle-role",
    methods=["POST"]
)
@login_required
def toggle_user_role(user_id):

    if not is_admin():
        return "Access Denied", 403

    # Prevent admin from changing own role
    if current_user.id == user_id:

        flash(
            "You cannot change your own role.",
            "error"
        )

        return redirect(
            url_for("admin_routes.admin_dashboard")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            id,
            role
        FROM users
        WHERE id = %s
    """, (user_id,))

    user = cursor.fetchone()

    if not user:

        cursor.close()
        connection.close()

        flash("User not found.", "error")

        return redirect(
            url_for("admin_routes.admin_dashboard")
        )

    # Toggle role
    new_role = (
        "admin"
        if user["role"] == "user"
        else "user"
    )

    cursor.execute("""
        UPDATE users
        SET role = %s
        WHERE id = %s
    """, (new_role, user_id))

    connection.commit()

    cursor.close()
    connection.close()

    flash(
        f"User role successfully changed to {new_role}.",
        "success"
    )

    return redirect(
        url_for("admin_routes.admin_dashboard")
    )


# ==================================================
# ACTIVATE / DEACTIVATE USER
# ==================================================

@admin_routes.route(
    "/admin/user/<int:user_id>/toggle-status",
    methods=["POST"]
)
@login_required
def toggle_user_status(user_id):

    if not is_admin():
        return "Access Denied", 403

    # Prevent admin from deactivating own account
    if current_user.id == user_id:

        flash(
            "You cannot deactivate your own account.",
            "error"
        )

        return redirect(
            url_for("admin_routes.admin_dashboard")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            id,
            is_active
        FROM users
        WHERE id = %s
    """, (user_id,))

    user = cursor.fetchone()

    if not user:

        cursor.close()
        connection.close()

        flash("User not found.", "error")

        return redirect(
            url_for("admin_routes.admin_dashboard")
        )

    new_status = (
        0
        if user["is_active"]
        else 1
    )

    cursor.execute("""
        UPDATE users
        SET is_active = %s
        WHERE id = %s
    """, (new_status, user_id))

    connection.commit()

    cursor.close()
    connection.close()

    status_message = (
        "activated"
        if new_status
        else "deactivated"
    )

    flash(
        f"User account successfully {status_message}.",
        "success"
    )

    return redirect(
        url_for("admin_routes.admin_dashboard")
    )


# ==================================================
# ACCEPT / REJECT CONTACT ADMIN REQUEST
# ==================================================

@admin_routes.route(
    "/admin/request/<int:request_id>/update",
    methods=["POST"]
)
@login_required
def update_user_request(request_id):

    if not is_admin():
        return "Access Denied", 403

    status = request.form.get(
        "status",
        ""
    ).strip()

    admin_response = request.form.get(
        "admin_response",
        ""
    ).strip()

    # Validate status
    if status not in ["Accepted", "Rejected"]:

        flash(
            "Invalid request status.",
            "error"
        )

        return redirect(
            url_for("admin_routes.admin_dashboard")
        )

    # Validate response length
    if len(admin_response) > 5000:

        flash(
            "Admin response must not exceed 5000 characters.",
            "error"
        )

        return redirect(
            url_for("admin_routes.admin_dashboard")
        )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Check whether request exists
    cursor.execute("""
        SELECT
            id,
            status
        FROM user_requests
        WHERE id = %s
    """, (request_id,))

    user_request = cursor.fetchone()

    if not user_request:

        cursor.close()
        connection.close()

        flash(
            "Request not found.",
            "error"
        )

        return redirect(
            url_for("admin_routes.admin_dashboard")
        )

    # Prevent reviewing an already processed request
    if user_request["status"] != "Pending":

        cursor.close()
        connection.close()

        flash(
            "This request has already been reviewed.",
            "error"
        )

        return redirect(
            url_for("admin_routes.admin_dashboard")
        )

    # Update request
    cursor.execute("""
        UPDATE user_requests
        SET
            status = %s,
            admin_response = %s
        WHERE
            id = %s
            AND status = 'Pending'
    """, (
        status,
        admin_response,
        request_id
    ))

    connection.commit()

    cursor.close()
    connection.close()

    flash(
        f"Request successfully {status.lower()}.",
        "success"
    )

    return redirect(
        url_for("admin_routes.admin_dashboard")
    )
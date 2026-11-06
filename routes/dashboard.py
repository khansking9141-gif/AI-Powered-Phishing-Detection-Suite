from flask import Blueprint, render_template
from flask_login import login_required, current_user

from database.db import get_db_connection


dashboard_routes = Blueprint(
    "dashboard_routes",
    __name__
)


@dashboard_routes.route("/dashboard")
@login_required
def dashboard():

    connection = get_db_connection()

    cursor = connection.cursor(dictionary=True)

    # -----------------------------------------
    # Get total scans for current user
    # -----------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM scans
        WHERE user_id = %s
        """,
        (current_user.id,)
    )

    total_scans = cursor.fetchone()["total"]


    # -----------------------------------------
    # Get URL scan count
    # -----------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM scans
        WHERE user_id = %s
        AND scan_type = 'URL'
        """,
        (current_user.id,)
    )

    url_scans = cursor.fetchone()["total"]


    # -----------------------------------------
    # Get QR scan count
    # -----------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM scans
        WHERE user_id = %s
        AND scan_type = 'QR'
        """,
        (current_user.id,)
    )

    qr_scans = cursor.fetchone()["total"]


    # -----------------------------------------
    # Get Email scan count
    # -----------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM scans
        WHERE user_id = %s
        AND scan_type = 'EMAIL'
        """,
        (current_user.id,)
    )

    email_scans = cursor.fetchone()["total"]


    # -----------------------------------------
    # Get phishing/threat count
    # -----------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM scans
        WHERE user_id = %s
        AND LOWER(risk_level) = 'phishing'
        """,
        (current_user.id,)
    )

    threats_detected = cursor.fetchone()["total"]


    # -----------------------------------------
    # Get safe scan count
    # -----------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM scans
        WHERE user_id = %s
        AND LOWER(risk_level) = 'safe'
        """,
        (current_user.id,)
    )

    safe_scans = cursor.fetchone()["total"]


    # -----------------------------------------
    # Get recent scans
    # -----------------------------------------

    cursor.execute(
        """
        SELECT
            id,
            scan_type,
            input_data,
            risk_score,
            risk_level,
            create_at
        FROM scans
        WHERE user_id = %s
        ORDER BY create_at DESC
        LIMIT 5
        """,
        (current_user.id,)
    )

    recent_scans = cursor.fetchall()


    cursor.close()
    connection.close()


    # -----------------------------------------
    # Send data to dashboard template
    # -----------------------------------------

    return render_template(
        "dashboard.html",

        total_scans=total_scans,
        url_scans=url_scans,
        qr_scans=qr_scans,
        email_scans=email_scans,
        threats_detected=threats_detected,
        safe_scans=safe_scans,
        recent_scans=recent_scans
    )
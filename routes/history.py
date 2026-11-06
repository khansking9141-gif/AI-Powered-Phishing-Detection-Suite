from flask import Blueprint, render_template
from flask_login import login_required, current_user

from database.db import get_db_connection


history_routes = Blueprint("history_routes", __name__)


@history_routes.route("/scan-history")
@login_required
def scan_history():

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
        SELECT
            id,
            scan_type,
            input_data,
            risk_score,
            risk_level,
            created_at
        FROM scans
        WHERE user_id = %s
        ORDER BY created_at DESC
    """

    cursor.execute(query, (current_user.id,))
    scans = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "scan_history.html",
        scans=scans
    )
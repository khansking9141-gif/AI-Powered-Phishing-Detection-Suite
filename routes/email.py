from flask import Blueprint, render_template, request, send_file
from flask_login import login_required, current_user
import os

from modules.email_detector import analyze_email
from modules.ai_analyzer import generate_ai_analysis
from database.db import get_db_connection
from reports.pdf_report import generate_pdf_report


email_routes = Blueprint("email_routes", __name__)


@email_routes.route("/email-scan", methods=["GET", "POST"])
@login_required
def email_scan():
    result = None

    if request.method == "POST":

        sender = request.form.get("sender", "").strip()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()

        # -----------------------------------------
        # Rule-based email phishing detection
        # -----------------------------------------
        result = analyze_email(
            sender,
            subject,
            body
        )

        # -----------------------------------------
        # Generative AI threat analysis
        # -----------------------------------------
        input_data = (
            f"Sender: {sender}\n"
            f"Subject: {subject}\n"
            f"Body: {body}"
        )

        ai_result = generate_ai_analysis(
            scan_type="EMAIL",
            input_data=input_data,
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            reasons=result["reasons"]
        )

        result["ai_analysis"] = ai_result

        # -----------------------------------------
        # Prepare database data
        # -----------------------------------------
        detection_result = "; ".join(
            result["reasons"]
        )

        ai_analysis = ai_result.get(
            "analysis",
            "AI analysis could not be generated."
        )

        # -----------------------------------------
        # Save scan to MySQL
        # -----------------------------------------
        connection = get_db_connection()
        cursor = connection.cursor()

        query = """
            INSERT INTO scans
            (
                user_id,
                scan_type,
                input_data,
                risk_score,
                risk_level,
                detection_result,
                ai_analysis
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        cursor.execute(
            query,
            (
                current_user.id,
                "EMAIL",
                input_data,
                result["risk_score"],
                result["risk_level"],
                detection_result,
                ai_analysis
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        # -----------------------------------------
        # Generate PDF Report
        # -----------------------------------------
        pdf_path = generate_pdf_report(
            username=current_user.username,
            scan_type="EMAIL",
            input_data=input_data,
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            reasons=result["reasons"],
            ai_analysis=ai_result.get(
                "analysis",
                "AI analysis could not be generated."
            ),
            recommendation=ai_result.get(
                "recommendation",
                "Use the risk score and detection reasons to make a security decision."
            )
        )

        result["pdf_path"] = pdf_path

    return render_template(
        "email_scan.html",
        result=result
    )


# -----------------------------------------
# Download Email PDF Report
# -----------------------------------------
@email_routes.route("/download-email-report")
@login_required
def download_email_report():

    filename = request.args.get("file")

    if not filename:
        return "Report not found", 404

    filepath = os.path.join(
        "reports",
        "generated",
        filename
    )

    if not os.path.exists(filepath):
        return "Report not found", 404

    return send_file(
        filepath,
        as_attachment=True,
        download_name=filename
    )
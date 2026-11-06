import os

from flask import Blueprint, render_template, request, send_file
from flask_login import login_required, current_user

from modules.url_detector import analyze_url
from modules.ai_analyzer import generate_ai_analysis
from database.db import get_db_connection
from reports.pdf_report import generate_pdf_report


# =========================================================
# URL BLUEPRINT
# =========================================================

url_routes = Blueprint(
    "url_routes",
    __name__
)


# =========================================================
# URL SCANNER
# =========================================================

@url_routes.route("/url-scan", methods=["GET", "POST"])
@login_required
def url_scan():

    result = None

    # -----------------------------------------------------
    # GET / POST
    # -----------------------------------------------------

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        # -------------------------------------------------
        # Make sure URL was provided
        # -------------------------------------------------

        if url:

            # =============================================
            # STEP 1: Analyze URL
            # =============================================

            result = analyze_url(url)

            # =============================================
            # STEP 2: Generative AI Analysis
            # =============================================

            ai_result = generate_ai_analysis(
                scan_type="URL",
                input_data=url,
                risk_score=result["risk_score"],
                risk_level=result["risk_level"],
                reasons=result["reasons"]
            )

            # Attach AI result to webpage result
            result["ai_result"] = ai_result

            # =============================================
            # STEP 3: Get AI Analysis Safely
            # =============================================

            ai_analysis = ""

            if ai_result:

                ai_analysis = ai_result.get(
                    "analysis",
                    ""
                )

            # =============================================
            # STEP 4: Prepare Detection Reasons
            # =============================================

            detection_result = "; ".join(
                result.get("reasons", [])
            )

            # =============================================
            # STEP 5: Save Scan to MySQL
            # =============================================

            connection = None
            cursor = None

            try:

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
                        "URL",
                        url,
                        result["risk_score"],
                        result["risk_level"],
                        detection_result,
                        ai_analysis
                    )
                )

                connection.commit()

            finally:

                if cursor:
                    cursor.close()

                if connection:
                    connection.close()

            # =============================================
            # STEP 6: Generate PDF Report
            # =============================================

            pdf_path = generate_pdf_report(
                username=current_user.username,
                scan_type="URL",
                input_data=url,
                risk_score=result["risk_score"],
                risk_level=result["risk_level"],
                reasons=result.get("reasons", []),
                ai_analysis=(
                    ai_result.get(
                        "analysis",
                        "AI analysis could not be generated."
                    )
                    if ai_result
                    else "AI analysis could not be generated."
                ),
                recommendation=(
                    ai_result.get(
                        "recommendation",
                        "Use the risk score and detection reasons to make a security decision."
                    )
                    if ai_result
                    else "Use the risk score and detection reasons to make a security decision."
                )
            )

            # =============================================
            # STEP 7: Attach PDF Information
            # =============================================

            result["pdf_path"] = pdf_path

            # IMPORTANT:
            # Extract the filename in Python instead of
            # using split('/')[-1] inside Jinja.
            result["pdf_filename"] = os.path.basename(
                pdf_path
            )

    # =====================================================
    # RENDER URL SCANNER
    # =====================================================

    return render_template(
        "url_scan.html",
        result=result
    )


# =========================================================
# DOWNLOAD URL PDF REPORT
# =========================================================

@url_routes.route("/download-url-report")
@login_required
def download_url_report():

    filename = request.args.get("file")

    # -----------------------------------------------------
    # Check filename
    # -----------------------------------------------------

    if not filename:

        return "Report not found", 404

    # -----------------------------------------------------
    # Security:
    # Only use the filename, never a complete user path.
    # -----------------------------------------------------

    filename = os.path.basename(filename)

    # -----------------------------------------------------
    # Build report path
    # -----------------------------------------------------

    filepath = os.path.join(
        "reports",
        "generated",
        filename
    )

    # -----------------------------------------------------
    # Check whether file exists
    # -----------------------------------------------------

    if not os.path.exists(filepath):

        return "Report not found", 404

    # -----------------------------------------------------
    # Send PDF
    # -----------------------------------------------------

    return send_file(
        filepath,
        as_attachment=True,
        download_name=filename
    )
import os
import uuid

from flask import Blueprint, render_template, request, send_file
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user

from modules.qr_detector import decode_qr
from modules.ai_analyzer import generate_ai_analysis
from database.db import get_db_connection
from reports.pdf_report import generate_pdf_report


# =========================================================
# QR BLUEPRINT
# =========================================================

qr_routes = Blueprint(
    "qr_routes",
    __name__
)


# =========================================================
# UPLOAD CONFIGURATION
# =========================================================

UPLOAD_FOLDER = "uploads"

ALLOWED_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp"
}

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# =========================================================
# QR SCANNER
# =========================================================

@qr_routes.route("/qr-scan", methods=["GET", "POST"])
@login_required
def qr_scan():

    result = None

    # -----------------------------------------------------
    # GET / POST
    # -----------------------------------------------------

    if request.method == "POST":

        qr_image = request.files.get("qr_image")

        # =================================================
        # CHECK UPLOADED FILE
        # =================================================

        if not qr_image or qr_image.filename == "":

            result = {
                "success": False,
                "data": None,
                "analysis": None,
                "ai_result": None,
                "pdf_path": None,
                "pdf_filename": None,
                "message": "Please select a QR code image."
            }

        elif not allowed_file(qr_image.filename):

            result = {
                "success": False,
                "data": None,
                "analysis": None,
                "ai_result": None,
                "pdf_path": None,
                "pdf_filename": None,
                "message": (
                    "Unsupported file type. "
                    "Please upload a PNG, JPG, JPEG, GIF, or WEBP image."
                )
            }

        else:

            # =================================================
            # CREATE UPLOADS FOLDER
            # =================================================

            os.makedirs(
                UPLOAD_FOLDER,
                exist_ok=True
            )

            # -------------------------------------------------
            # Use secure and unique filename
            # -------------------------------------------------

            original_filename = secure_filename(
                qr_image.filename
            )

            extension = os.path.splitext(
                original_filename
            )[1].lower()

            filename = f"{uuid.uuid4().hex}{extension}"

            file_path = os.path.join(
                UPLOAD_FOLDER,
                filename
            )

            # -------------------------------------------------
            # Save uploaded QR image
            # -------------------------------------------------

            qr_image.save(file_path)

            # =================================================
            # DECODE AND ANALYZE QR CODE
            # =================================================

            result = decode_qr(file_path)

            # =================================================
            # GENERATIVE AI ANALYSIS
            # =================================================

            if result["success"] and result["analysis"]:

                analysis = result["analysis"]

                ai_result = generate_ai_analysis(
                    scan_type="QR",
                    input_data=result["data"],
                    risk_score=analysis["risk_score"],
                    risk_level=analysis["risk_level"],
                    reasons=analysis["reasons"]
                )

                # -------------------------------------------------
                # Attach AI result
                # -------------------------------------------------

                result["ai_result"] = ai_result

                # =================================================
                # GET AI EXPLANATION SAFELY
                # =================================================

                ai_analysis = ""

                if ai_result:

                    ai_analysis = ai_result.get(
                        "analysis",
                        ""
                    )

                # =================================================
                # DETECTION REASONS
                # =================================================

                detection_result = "; ".join(
                    analysis.get("reasons", [])
                )

                # =================================================
                # SAVE QR SCAN TO MYSQL
                # =================================================

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
                            "QR",
                            result["data"],
                            analysis["risk_score"],
                            analysis["risk_level"],
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

                # =================================================
                # GENERATE PDF REPORT
                # =================================================

                pdf_path = generate_pdf_report(
                    username=current_user.username,
                    scan_type="QR",
                    input_data=result["data"],
                    risk_score=analysis["risk_score"],
                    risk_level=analysis["risk_level"],
                    reasons=analysis.get("reasons", []),
                    ai_analysis=(
                        ai_result.get(
                            "analysis",
                            "AI analysis could not be generated."
                        )
                        if ai_result
                        else
                        "AI analysis could not be generated."
                    ),
                    recommendation=(
                        ai_result.get(
                            "recommendation",
                            "Use the risk score and detection reasons to make a security decision."
                        )
                        if ai_result
                        else
                        "Use the risk score and detection reasons to make a security decision."
                    )
                )

                # =================================================
                # ATTACH PDF INFORMATION
                # =================================================

                result["pdf_path"] = pdf_path

                # IMPORTANT:
                # Extract the filename in Python rather than
                # using split('/')[-1] inside Jinja.

                result["pdf_filename"] = os.path.basename(
                    pdf_path
                )


    # =====================================================
    # RENDER QR SCANNER
    # =====================================================

    return render_template(
        "qr_scan.html",
        result=result
    )


# =========================================================
# DOWNLOAD QR PDF REPORT
# =========================================================

@qr_routes.route("/download-qr-report")
@login_required
def download_qr_report():

    filename = request.args.get("file")

    # -----------------------------------------------------
    # Check filename
    # -----------------------------------------------------

    if not filename:

        return "Report not found", 404

    # -----------------------------------------------------
    # Security:
    # Only use the filename
    # -----------------------------------------------------

    filename = os.path.basename(
        filename
    )

    # -----------------------------------------------------
    # Build report path
    # -----------------------------------------------------

    filepath = os.path.join(
        "reports",
        "generated",
        filename
    )

    # -----------------------------------------------------
    # Check file
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
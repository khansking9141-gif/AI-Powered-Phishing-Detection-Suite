import cv2
import re
import os
import ipaddress

from urllib.parse import urlparse, urlsplit

from modules.url_detector import analyze_url


# ---------------------------------------------------------
# RISK LEVEL CLASSIFICATION
# ---------------------------------------------------------

def classify_risk(score):

    score = max(0, min(100, int(score)))

    if score <= 30:
        return "Safe"

    elif score <= 69:
        return "Suspicious"

    else:
        return "Phishing"


# ---------------------------------------------------------
# URL DETECTION
# ---------------------------------------------------------

def extract_urls(text):

    if not text:
        return []

    pattern = re.compile(
        r'(?i)\b(?:https?://|www\.)[^\s<>"\']+'
        r'|(?<![@\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}'
        r'(?:/[^\s<>"\']*)?'
    )

    matches = pattern.findall(text)

    cleaned_urls = []

    for item in matches:

        item = item.rstrip(".,;:!?)\"]}")

        if item.lower().startswith("www."):
            item = "https://" + item

        elif not item.lower().startswith(("http://", "https://")):
            item = "https://" + item

        if item not in cleaned_urls:
            cleaned_urls.append(item)

    return cleaned_urls


# ---------------------------------------------------------
# URL PAYLOAD ANALYSIS
# ---------------------------------------------------------

def analyze_qr_url(url):

    try:

        result = analyze_url(url)

        score = int(result.get("risk_score", 0))

        return {
            "risk_score": max(0, min(100, score)),
            "risk_level": classify_risk(score),
            "reasons": result.get("reasons", []),
            "payload_type": "URL"
        }

    except Exception as e:

        return {
            "risk_score": 50,
            "risk_level": "Suspicious",
            "reasons": [
                "The URL could not be analyzed successfully.",
                str(e)
            ],
            "payload_type": "URL"
        }


# ---------------------------------------------------------
# NON-URL QR PAYLOAD ANALYSIS
# ---------------------------------------------------------

def analyze_text_payload(data):

    score = 5
    reasons = []

    text = data.strip()
    lower_text = text.lower()

    # -----------------------------------------
    # 1. Detect dangerous executable schemes
    # -----------------------------------------

    dangerous_schemes = [
        "javascript:",
        "data:",
        "file:",
        "vbscript:",
        "intent:",
        "filesystem:"
    ]

    for scheme in dangerous_schemes:

        if lower_text.startswith(scheme):

            score += 85

            reasons.append(
                f"QR code contains a potentially dangerous "
                f"or executable URI scheme: {scheme}"
            )

    # -----------------------------------------
    # 2. Detect embedded URLs
    # -----------------------------------------

    urls = extract_urls(text)

    if urls:

        url_results = []

        for url in urls:
            url_results.append(analyze_qr_url(url))

        highest_result = max(
            url_results,
            key=lambda item: item["risk_score"]
        )

        score = max(score, highest_result["risk_score"])

        reasons.extend(highest_result["reasons"])

        if len(urls) > 1:

            reasons.append(
                "QR code contains multiple URLs."
            )

        return {
            "risk_score": min(100, score),
            "risk_level": classify_risk(score),
            "reasons": list(dict.fromkeys(reasons)),
            "payload_type": "URL"
        }

    # -----------------------------------------
    # 3. Wi-Fi QR codes
    # -----------------------------------------

    if lower_text.startswith("wifi:"):

        reasons.append(
            "QR code contains Wi-Fi configuration information."
        )

        # Wi-Fi configuration is not inherently malicious.
        # Do not classify it as phishing based on format alone.

        score = 5

        return {
            "risk_score": score,
            "risk_level": "Safe",
            "reasons": reasons,
            "payload_type": "WiFi Configuration"
        }

    # -----------------------------------------
    # 4. Email QR codes
    # -----------------------------------------

    if lower_text.startswith("mailto:"):

        reasons.append(
            "QR code contains an email address or email action."
        )

        score = 25

        if re.search(
            r'password|otp|pin|bank|payment|verify|login|account',
            lower_text
        ):

            score += 20

            reasons.append(
                "Email action contains sensitive account or payment-related terms."
            )

        return {
            "risk_score": min(100, score),
            "risk_level": classify_risk(score),
            "reasons": reasons,
            "payload_type": "Email"
        }

    # -----------------------------------------
    # 5. Telephone QR codes
    # -----------------------------------------

    if lower_text.startswith("tel:"):

        reasons.append(
            "QR code contains a telephone number."
        )

        return {
            "risk_score": 10,
            "risk_level": "Safe",
            "reasons": reasons,
            "payload_type": "Telephone"
        }

    # -----------------------------------------
    # 6. Payment QR codes
    # -----------------------------------------

    payment_schemes = [
        "upi://",
        "bitcoin:",
        "ethereum:",
        "litecoin:"
    ]

    for scheme in payment_schemes:

        if lower_text.startswith(scheme):

            score = 35

            reasons.append(
                "QR code contains a payment or cryptocurrency URI. "
                "Verify the recipient and payment details before proceeding."
            )

            return {
                "risk_score": score,
                "risk_level": "Suspicious",
                "reasons": reasons,
                "payload_type": "Payment"
            }

    # -----------------------------------------
    # 7. Detect contact information
    # -----------------------------------------

    if (
        "begin:vcard" in lower_text
        or "begin:vcf" in lower_text
    ):

        reasons.append(
            "QR code contains contact card information."
        )

        return {
            "risk_score": 10,
            "risk_level": "Safe",
            "reasons": reasons,
            "payload_type": "Contact"
        }

    # -----------------------------------------
    # 8. Detect suspicious text patterns
    # -----------------------------------------

    suspicious_patterns = {

        "credential request": (
            r'enter.{0,30}(password|otp|pin|cvv)|'
            r'share.{0,30}(password|otp|pin)|'
            r'provide.{0,30}(password|otp|pin)'
        ),

        "urgent action": (
            r'urgent action|required immediately|'
            r'account suspended|account blocked|'
            r'limited time'
        ),

        "financial request": (
            r'send money|transfer money|'
            r'claim refund|claim reward|'
            r'payment required'
        ),

        "sensitive information request": (
            r'bank details|card number|'
            r'credit card|debit card|'
            r'personal information'
        )
    }

    for category, pattern in suspicious_patterns.items():

        if re.search(pattern, lower_text):

            score += 20

            reasons.append(
                f"QR text contains a suspicious pattern: {category}."
            )

    # -----------------------------------------
    # 9. Detect suspicious redirection language
    # -----------------------------------------

    redirection_words = [
        "click here",
        "scan again",
        "verify your account",
        "login immediately",
        "update your account",
        "confirm your identity"
    ]

    for word in redirection_words:

        if word in lower_text:

            score += 10

            reasons.append(
                f"QR text contains potentially suspicious instructions: {word}."
            )

    # -----------------------------------------
    # 10. Empty or unusually large payload
    # -----------------------------------------

    if not text:

        score = 50

        reasons.append(
            "QR code contains empty content."
        )

    if len(text) > 2000:

        score += 10

        reasons.append(
            "QR code contains unusually large text content."
        )

    # -----------------------------------------
    # FINAL RESULT
    # -----------------------------------------

    score = min(100, score)

    if not reasons:

        reasons.append(
            "No obvious suspicious patterns were detected in the QR text. "
            "This does not guarantee that the content is trustworthy."
        )

    return {
        "risk_score": score,
        "risk_level": classify_risk(score),
        "reasons": list(dict.fromkeys(reasons)),
        "payload_type": "Text"
    }


# ---------------------------------------------------------
# QR IMAGE DECODING
# ---------------------------------------------------------

def decode_qr(image_path):

    try:

        if not os.path.isfile(image_path):

            return {
                "success": False,
                "data": None,
                "is_url": False,
                "analysis": None,
                "message": "Uploaded image file does not exist."
            }

        image = cv2.imread(image_path)

        if image is None:

            return {
                "success": False,
                "data": None,
                "is_url": False,
                "analysis": None,
                "message": "Unable to read the uploaded image."
            }

        detector = cv2.QRCodeDetector()

        decoded_data = None

        # -----------------------------------------
        # Try original image
        # -----------------------------------------

        qr_data, points, _ = detector.detectAndDecode(image)

        if qr_data:

            decoded_data = qr_data

        # -----------------------------------------
        # Try multi-QR detection
        # -----------------------------------------

        if not decoded_data:

            try:

                result = detector.detectAndDecodeMulti(image)

                if result and result[0]:

                    decoded_values = result[1]

                    for value in decoded_values:

                        if value and value.strip():

                            decoded_data = value

                            break

            except Exception:
                pass

        # -----------------------------------------
        # Try enhanced image versions
        # -----------------------------------------

        if not decoded_data:

            gray = cv2.cvtColor(
                image,
                cv2.COLOR_BGR2GRAY
            )

            height, width = gray.shape

            if max(height, width) < 1500:

                scale = 2

                gray = cv2.resize(
                    gray,
                    None,
                    fx=scale,
                    fy=scale,
                    interpolation=cv2.INTER_CUBIC
                )

            # Grayscale image
            qr_data, _, _ = detector.detectAndDecode(gray)

            if qr_data:

                decoded_data = qr_data

            # Adaptive threshold image
            if not decoded_data:

                threshold = cv2.adaptiveThreshold(
                    gray,
                    255,
                    cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                    cv2.THRESH_BINARY,
                    31,
                    2
                )

                qr_data, _, _ = detector.detectAndDecode(threshold)

                if qr_data:

                    decoded_data = qr_data

        # -----------------------------------------
        # No QR found
        # -----------------------------------------

        if not decoded_data:

            return {
                "success": False,
                "data": None,
                "is_url": False,
                "analysis": None,
                "message": "No readable QR code was detected in the image."
            }

        qr_data = decoded_data.strip()

        # -----------------------------------------
        # Analyze decoded QR content
        # -----------------------------------------

        analysis = analyze_text_payload(qr_data)

        is_url = (
            analysis.get("payload_type") == "URL"
        )

        return {
            "success": True,
            "data": qr_data,
            "is_url": is_url,
            "analysis": analysis,
            "message": "QR code successfully decoded and analyzed."
        }

    except Exception as e:

        return {
            "success": False,
            "data": None,
            "is_url": False,
            "analysis": None,
            "message": (
                "An error occurred while processing the QR code: "
                + str(e)
            )
        }
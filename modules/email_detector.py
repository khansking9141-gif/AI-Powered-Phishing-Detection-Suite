"""
PhishGuard Advanced Email Phishing Detector

Public interface:

    analyze_email(sender, subject, body)

Returns:

    {
        "risk_score": int,
        "risk_level": str,
        "reasons": list
    }

Detection approach:
    - Sender analysis
    - Domain analysis
    - Brand impersonation
    - URL analysis
    - Credential theft detection
    - Financial fraud detection
    - Social engineering detection
    - Contextual risk scoring

Limitations:
    This version analyzes sender, subject and body text.
    It cannot independently verify SPF, DKIM, DMARC,
    inspect actual attachments, or determine live URL reputation.
"""

import re
import ipaddress
import html
import unicodedata

from email.utils import parseaddr
from urllib.parse import (
    urlsplit,
    unquote,
    parse_qs
)
from difflib import SequenceMatcher


# ==========================================================
# CONFIGURATION
# ==========================================================

SAFE_THRESHOLD = 30
PHISHING_THRESHOLD = 70


# ==========================================================
# KNOWN BRANDS
# ==========================================================

BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com"],
    "google": ["google.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "whatsapp": ["whatsapp.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "github": ["github.com"],
    "yahoo": ["yahoo.com"],
    "twitter": ["twitter.com", "x.com"],
    "telegram": ["telegram.org"],
    "spotify": ["spotify.com"],
    "discord": ["discord.com"],
    "wikipedia": ["wikipedia.org"],

    "sbi": ["sbi.co.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "axisbank": ["axisbank.com"],
    "onlinesbi": ["onlinesbi.sbi"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["google.com"],
    "flipkart": ["flipkart.com"],
    "irctc": ["irctc.co.in"]
}


# ==========================================================
# URL SHORTENERS
# ==========================================================

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly",
    "buff.ly",
    "tiny.cc",
    "lnkd.in",
    "s.id"
}


# ==========================================================
# SUSPICIOUS DOMAIN TERMS
# ==========================================================

SUSPICIOUS_DOMAIN_TERMS = {
    "account-security",
    "account-verify",
    "bank-alert",
    "free-gift",
    "login-support",
    "password-reset",
    "prize-claim",
    "reward-center",
    "secure-login",
    "security-alert",
    "verify-account",
    "winner-notification"
}


# ==========================================================
# EMAIL ACTION KEYWORDS
# ==========================================================

SENSITIVE_INFORMATION = (
    r"password|passcode|credential|username|"
    r"otp|one[- ]time password|verification code|"
    r"security code|pin|cvv|cvc|"
    r"card details|bank details|"
    r"bank account number|credit card|"
    r"debit card|recovery phrase|seed phrase|"
    r"private key|authentication code"
)


ACTION_WORDS = (
    r"enter|provide|send|share|submit|"
    r"reply with|type|upload|disclose|"
    r"reveal|forward|confirm|update"
)


# ==========================================================
# GENERAL HELPERS
# ==========================================================

def _add_indicator(indicators, key, points, reason):

    if key not in indicators:

        indicators[key] = {
            "points": points,
            "reason": reason
        }


def _calculate_score(indicators):

    score = sum(
        item["points"]
        for item in indicators.values()
    )

    return max(0, min(int(score), 100))


def _classify(score, reasons):

    score = max(0, min(int(score), 100))

    if score >= PHISHING_THRESHOLD:

        level = "Phishing"

    elif score > SAFE_THRESHOLD:

        level = "Suspicious"

    else:

        level = "Safe"

    if not reasons:

        reasons = [
            "No significant phishing indicators were detected by the available email checks."
        ]

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons
    }


def _contains_pattern(text, patterns):

    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in patterns
    )


# ==========================================================
# EMAIL ADDRESS VALIDATION
# ==========================================================

def _valid_email_address(value):

    if not value:

        return False, "", ""

    display_name, address = parseaddr(value)

    if not address or any(ch.isspace() for ch in address):

        return False, "", display_name

    if address.count("@") != 1:

        return False, "", display_name

    local, domain = address.rsplit("@", 1)

    if not local or not domain:

        return False, "", display_name

    try:

        domain = domain.encode("idna").decode("ascii").lower()

    except UnicodeError:

        return False, "", display_name

    if len(address) > 254 or len(local) > 64:

        return False, "", display_name

    if (
        domain.startswith(".")
        or domain.endswith(".")
        or ".." in domain
    ):

        return False, "", display_name

    if not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+",
        local
    ):

        return False, "", display_name

    if not re.fullmatch(
        r"[A-Za-z0-9.-]+",
        domain
    ):

        return False, "", display_name

    labels = domain.split(".")

    if len(labels) < 2:

        return False, "", display_name

    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):

        return False, "", display_name

    return True, domain, display_name


# ==========================================================
# DOMAIN HELPERS
# ==========================================================

def _registered_domain(domain):

    """
    Approximate registrable-domain extraction.

    A production implementation should use a maintained
    Public Suffix List.
    """

    parts = domain.lower().split(".")

    if len(parts) <= 2:

        return domain.lower()

    common_suffixes = {
        "co.in",
        "com.au",
        "co.uk",
        "co.jp",
        "com.br",
        "co.nz",
        "com.sg",
        "com.cn",
        "org.uk",
        "net.au"
    }

    last_two = ".".join(parts[-2:])

    if last_two in common_suffixes:

        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def _is_official_domain(domain, official_domains):

    return any(
        domain == official
        or domain.endswith("." + official)
        for official in official_domains
    )


# ==========================================================
# BRAND IMPERSONATION
# ==========================================================

def _check_brand_impersonation(domain, display_name):

    findings = []

    registered = _registered_domain(domain)

    labels = set(domain.split("."))

    for brand, official_domains in BRANDS.items():

        if _is_official_domain(domain, official_domains):

            continue

        if brand in labels or brand in registered.split(".")[0]:

            findings.append(
                f"The sender domain may impersonate the brand '{brand}'."
            )

            continue

        # Check possible lookalike spellings.

        domain_label = registered.split(".")[0]

        if len(brand) >= 5 and len(domain_label) >= 5:

            similarity = SequenceMatcher(
                None,
                brand,
                domain_label
            ).ratio()

            if similarity >= 0.86:

                findings.append(
                    f"The sender domain resembles the brand '{brand}' and may be a lookalike."
                )

    # Display-name impersonation.

    display_lower = display_name.lower()

    for brand, official_domains in BRANDS.items():

        if brand in display_lower:

            if not _is_official_domain(domain, official_domains):

                findings.append(
                    f"The sender display name mentions '{brand}', but the sender domain is not an obvious official domain."
                )

    return list(dict.fromkeys(findings))


# ==========================================================
# URL EXTRACTION
# ==========================================================

URL_PATTERN = re.compile(
    r"""(?i)\b(?:(?:https?://)|(?:www\.))"""
    r"""[^\s<>"']+"""
)


def _extract_urls(text):

    decoded = html.unescape(text or "")

    urls = URL_PATTERN.findall(decoded)

    cleaned = []

    for url in urls:

        url = url.rstrip(".,;:!?)]}>'\"")

        if url and url not in cleaned:

            cleaned.append(url)

    return cleaned


# ==========================================================
# EMAIL URL ANALYSIS
# ==========================================================

def _analyze_email_url(raw_url):

    points = 0
    reasons = []

    candidate = raw_url.strip()

    if not re.match(
        r"^https?://",
        candidate,
        re.IGNORECASE
    ):

        candidate = "https://" + candidate

    try:

        parsed = urlsplit(candidate)

        host = parsed.hostname

        if not host:

            return 15, [
                "An email link has no recognizable destination hostname."
            ]

        host = host.lower().rstrip(".")

        _ = parsed.port

    except ValueError:

        return 15, [
            "An email link appears malformed."
        ]

    # IP address.

    try:

        ipaddress.ip_address(host)

        points += 25

        reasons.append(
            "An email link points directly to an IP address."
        )

    except ValueError:

        pass

    # Punycode.

    if "xn--" in host:

        points += 15

        reasons.append(
            "An email link uses Punycode encoding."
        )

    # Embedded credentials.

    if parsed.username is not None or parsed.password is not None:

        points += 20

        reasons.append(
            "An email link contains embedded user information."
        )

    # HTTP.

    if parsed.scheme.lower() == "http":

        points += 8

        reasons.append(
            "An email link uses unencrypted HTTP."
        )

    # Shorteners.

    if host in SHORTENER_DOMAINS:

        points += 15

        reasons.append(
            "An email link uses a URL shortening service."
        )

    # Brand impersonation in URL.

    registered = _registered_domain(host)

    for brand, official_domains in BRANDS.items():

        if brand in host and not _is_official_domain(
            host,
            official_domains
        ):

            points += 30

            reasons.append(
                f"An email link may imitate the legitimate '{brand}' domain."
            )

            break

    # Excessive subdomains.

    if len(host.split(".")) >= 5:

        points += 8

        reasons.append(
            "An email link contains an unusually large number of subdomains."
        )

    # Suspicious URL terms.

    url_text = (
        host + " " +
        unquote(parsed.path) + " " +
        parsed.query
    ).lower()

    if _contains_pattern(
        url_text,
        [
            r"\baccount[-_]?verify\b",
            r"\bpassword[-_]?steal\b",
            r"\bclaim[-_]?prize\b",
            r"\bfree[-_]?gift\b",
            r"\bcollect[-_]?payment\b",
            r"\botp[-_]?verify\b",
            r"\bcredential[-_]?check\b"
        ]
    ):

        points += 15

        reasons.append(
            "An email link contains potentially deceptive security or reward-related URL terms."
        )

    return min(points, 70), reasons


# ==========================================================
# CREDENTIAL THEFT DETECTION
# ==========================================================

def _check_credential_theft(text):

    findings = []

    request_pattern = re.compile(
        r"\b(?:" + ACTION_WORDS + r")\b"
        r"[^.!?\n]{0,100}?"
        r"\b(?:" + SENSITIVE_INFORMATION + r")\b",
        re.IGNORECASE
    )

    reverse_pattern = re.compile(
        r"\b(?:" + SENSITIVE_INFORMATION + r")\b"
        r"[^.!?\n]{0,100}?"
        r"\b(?:" + ACTION_WORDS + r")\b",
        re.IGNORECASE
    )

    if request_pattern.search(text) or reverse_pattern.search(text):

        # Do not treat explicit warnings against disclosure
        # as credential theft requests.

        warning = re.search(
            r"\b(?:never|do not|don't|will never|will not|won't)\b"
            r"[^.!?\n]{0,100}?"
            r"\b(?:ask|request|share|send|provide|enter|disclose)\b",
            text,
            re.IGNORECASE
        )

        if not warning:

            findings.append(
                "The email appears to request sensitive information such as passwords, OTPs, PINs, or financial details."
            )

    # Explicit OTP harvesting.

    if re.search(
        r"\b(?:share|send|reply with|provide|enter|tell us)"
        r"[^.!?\n]{0,60}\b(?:otp|one[- ]time password|verification code)\b",
        text,
        re.IGNORECASE
    ):

        findings.append(
            "The email requests an OTP or verification code."
        )

    # Recovery phrase / private key requests.

    if re.search(
        r"\b(?:seed phrase|recovery phrase|private key)\b"
        r"[^.!?\n]{0,70}\b(?:send|share|enter|provide|reveal|submit)\b",
        text,
        re.IGNORECASE
    ):

        findings.append(
            "The email requests sensitive cryptocurrency wallet recovery information."
        )

    return list(dict.fromkeys(findings))


# ==========================================================
# SOCIAL ENGINEERING
# ==========================================================

def _check_social_engineering(text):

    findings = []

    urgency = [
        r"\burgent(?:ly)?\b",
        r"\bimmediately\b",
        r"\bright away\b",
        r"\bact now\b",
        r"\baction required\b",
        r"\bfinal notice\b",
        r"\bfinal warning\b",
        r"\bwithout delay\b",
        r"\brespond immediately\b",
        r"\blast chance\b",
        r"\bwithin\s+\d+\s*(?:minutes?|hours?)\b"
    ]

    urgency_hits = sum(
        bool(re.search(pattern, text, re.IGNORECASE))
        for pattern in urgency
    )

    if urgency_hits >= 2:

        findings.append(
            "The message uses repeated urgency or time-pressure language."
        )

    threats = [
        r"\byour account will be (?:blocked|suspended|closed|deleted)\b",
        r"\bpermanently (?:blocked|suspended|disabled)\b",
        r"\baccess will be denied\b",
        r"\bfailure to.{0,40}(?:verify|respond|confirm)\b",
        r"\bimmediate account termination\b"
    ]

    if _contains_pattern(text, threats):

        findings.append(
            "The message threatens account suspension, closure, or loss of access."
        )

    manipulation = [
        r"\bdo not tell anyone\b",
        r"\bkeep this secret\b",
        r"\bkeep this confidential\b",
        r"\bignore security warnings\b",
        r"\bdisable your antivirus\b",
        r"\bbypass security\b",
        r"\bdo not contact customer support\b",
        r"\bdo not contact your bank\b"
    ]

    if _contains_pattern(text, manipulation):

        findings.append(
            "The message encourages secrecy or bypassing normal security procedures."
        )

    return findings


# ==========================================================
# FINANCIAL FRAUD
# ==========================================================

def _check_financial_fraud(text):

    findings = []

    patterns = [

        (
            r"\b(?:processing fee|release fee|claim fee|"
            r"registration fee|refundable fee)\b",
            "The email requests a fee associated with a supposed reward or service."
        ),

        (
            r"\b(?:wire transfer|transfer money|send money|"
            r"gift card payment)\b",
            "The email contains potentially suspicious money-transfer instructions."
        ),

        (
            r"\b(?:claim your refund|refund pending|"
            r"refund waiting|refund will expire)\b",
            "The email uses a refund claim that may be designed to manipulate the recipient."
        ),

        (
            r"\b(?:change|update|replace|modify)\b"
            r"[^.!?\n]{0,70}\b(?:bank account|bank details|payment details)\b",
            "The email requests a change to financial or bank account details."
        ),

        (
            r"\b(?:new bank account|updated bank details|"
            r"revised payment instructions)\b",
            "The email contains changed banking or payment instructions that should be independently verified."
        ),

        (
            r"\b(?:pay|transfer|send)\b"
            r"[^.!?\n]{0,60}\b(?:immediately|urgent|today)\b",
            "The email combines payment instructions with urgency."
        )
    ]

    for pattern, reason in patterns:

        if re.search(pattern, text, re.IGNORECASE):

            findings.append(reason)

    return findings


# ==========================================================
# REWARD AND LOTTERY SCAMS
# ==========================================================

def _check_reward_scams(text):

    patterns = [
        r"\byou have been selected\b",
        r"\byou are a winner\b",
        r"\blucky winner\b",
        r"\bclaim your prize\b",
        r"\bclaim your reward\b",
        r"\bunclaimed prize\b",
        r"\binternational lottery\b",
        r"\bfree gift\b",
        r"\bwon\b.{0,50}\b(?:prize|reward|cash|money)\b"
    ]

    if _contains_pattern(text, patterns):

        return [
            "The email contains an unexpected prize, lottery, or reward claim."
        ]

    return []


# ==========================================================
# ACCOUNT SECURITY NOTIFICATIONS
# ==========================================================

def _check_security_context(text):

    findings = []

    security_alert = [
        r"\bunauthori[sz]ed activity\b",
        r"\bunusual activity\b",
        r"\bsuspicious activity\b",
        r"\bunrecognized login\b",
        r"\bunknown device detected\b",
        r"\bnew device detected\b",
        r"\bsecurity breach\b",
        r"\baccount compromised\b"
    ]

    if _contains_pattern(text, security_alert):

        findings.append(
            "The message reports unusual account activity; verify the notification through the official service."
        )

    return findings


# ==========================================================
# ATTACHMENT INSTRUCTIONS
# ==========================================================

def _check_attachments(text):

    findings = []

    dangerous_instructions = [
        r"\benable macros\b",
        r"\bdisable security\b",
        r"\brun the attached file\b",
        r"\bopen the attached executable\b",
        r"\binstall the attached file\b",
        r"\bdisable antivirus\b",
        r"\bexecute the attachment\b"
    ]

    if _contains_pattern(text, dangerous_instructions):

        findings.append(
            "The email instructs the recipient to execute files or weaken security protections."
        )

    elif re.search(
        r"\b(?:open|download) (?:the |an )?attachment\b",
        text,
        re.IGNORECASE
    ):

        findings.append(
            "The email asks the recipient to open or download an attachment; verify it first."
        )

    return findings


# ==========================================================
# MAIN EMAIL ANALYZER
# ==========================================================

def analyze_email(sender, subject, body):

    """
    Analyze email sender, subject and body.

    Compatible with existing PhishGuard integration.
    """

    sender = str(sender or "").strip()
    subject = str(subject or "").strip()
    body = str(body or "").strip()

    if not (sender or subject or body):

        return _classify(
            0,
            ["No email content was provided."]
        )

    # Decode HTML entities and normalize whitespace.

    body = html.unescape(body)

    body = re.sub(
        r"\s+",
        " ",
        body
    ).strip()

    subject_body = f"{subject} {body}"

    combined = f"{sender} {subject} {body}"

    normalized_text = unicodedata.normalize(
        "NFKC",
        combined
    ).lower()

    indicators = {}

    # ======================================================
    # 1. SENDER VALIDATION
    # ======================================================

    valid_sender, domain, display_name = _valid_email_address(sender)

    if sender and not valid_sender:

        _add_indicator(
            indicators,
            "invalid_sender",
            5,
            "The sender field does not contain a standard email address."
        )

    elif valid_sender:

        # Punycode.

        if "xn--" in domain:

            _add_indicator(
                indicators,
                "sender_punycode",
                15,
                "The sender domain contains Punycode encoding."
            )

        # Suspicious domain terms.

        if any(
            term in domain
            for term in SUSPICIOUS_DOMAIN_TERMS
        ):

            _add_indicator(
                indicators,
                "suspicious_sender_terms",
                12,
                "The sender domain contains wording commonly associated with deceptive security or reward addresses."
            )

        # IP address in sender domain.

        try:

            ipaddress.ip_address(domain)

            _add_indicator(
                indicators,
                "sender_ip",
                25,
                "The sender uses an IP address instead of a normal domain."
            )

        except ValueError:

            pass

        # Brand impersonation.

        brand_findings = _check_brand_impersonation(
            domain,
            display_name
        )

        for index, reason in enumerate(brand_findings):

            _add_indicator(
                indicators,
                f"brand_impersonation_{index}",
                25,
                reason
            )

    # ======================================================
    # 2. SUBJECT ANALYSIS
    # ======================================================

    subject_lower = subject.lower()

    if re.search(
        r"\b(?:urgent|final warning|account suspended|"
        r"immediate action|payment overdue|security alert)\b",
        subject_lower
    ):

        _add_indicator(
            indicators,
            "suspicious_subject",
            5,
            "The subject contains urgent or security-related wording."
        )

    # ======================================================
    # 3. SOCIAL ENGINEERING
    # ======================================================

    social_findings = _check_social_engineering(
        subject_body
    )

    for index, reason in enumerate(social_findings):

        _add_indicator(
            indicators,
            f"social_engineering_{index}",
            15,
            reason
        )

    # ======================================================
    # 4. CREDENTIAL THEFT
    # ======================================================

    credential_findings = _check_credential_theft(
        subject_body
    )

    for index, reason in enumerate(credential_findings):

        _add_indicator(
            indicators,
            f"credential_theft_{index}",
            35,
            reason
        )

    # ======================================================
    # 5. FINANCIAL FRAUD
    # ======================================================

    financial_findings = _check_financial_fraud(
        subject_body
    )

    for index, reason in enumerate(financial_findings):

        _add_indicator(
            indicators,
            f"financial_fraud_{index}",
            18,
            reason
        )

    # ======================================================
    # 6. REWARD SCAMS
    # ======================================================

    reward_findings = _check_reward_scams(
        subject_body
    )

    for index, reason in enumerate(reward_findings):

        _add_indicator(
            indicators,
            f"reward_scam_{index}",
            25,
            reason
        )

    # ======================================================
    # 7. SECURITY CONTEXT
    # ======================================================

    security_findings = _check_security_context(
        subject_body
    )

    for index, reason in enumerate(security_findings):

        _add_indicator(
            indicators,
            f"security_context_{index}",
            5,
            reason
        )

    # ======================================================
    # 8. ACCOUNT VERIFICATION
    # ======================================================

    verification_patterns = [
        r"\bverify your account\b",
        r"\bconfirm your account\b",
        r"\bverify your identity\b",
        r"\breactivate your account\b",
        r"\brestore your access\b",
        r"\bcomplete the verification\b",
        r"\breset your password\b",
        r"\bupdate your password\b"
    ]

    if _contains_pattern(
        subject_body,
        verification_patterns
    ):

        _add_indicator(
            indicators,
            "account_verification",
            7,
            "The email requests an account verification or password-reset action."
        )

    # ======================================================
    # 9. URL ANALYSIS
    # ======================================================

    urls = _extract_urls(body)

    if urls:

        _add_indicator(
            indicators,
            "email_links",
            2,
            f"The email contains {len(urls)} visible link(s); their destinations should be inspected."
        )

        highest_url_score = 0
        all_url_reasons = []

        for url in urls:

            url_score, url_reasons = _analyze_email_url(
                url
            )

            highest_url_score = max(
                highest_url_score,
                url_score
            )

            for reason in url_reasons:

                if reason not in all_url_reasons:

                    all_url_reasons.append(reason)

        if highest_url_score:

            _add_indicator(
                indicators,
                "risky_email_url",
                highest_url_score,
                "At least one email link contains suspicious URL characteristics."
            )

            for index, reason in enumerate(all_url_reasons):

                _add_indicator(
                    indicators,
                    f"url_reason_{index}",
                    0,
                    reason
                )

    # ======================================================
    # 10. ATTACHMENT ANALYSIS
    # ======================================================

    attachment_findings = _check_attachments(
        subject_body
    )

    for index, reason in enumerate(attachment_findings):

        _add_indicator(
            indicators,
            f"attachment_{index}",
            20,
            reason
        )

    # ======================================================
    # 11. CONTEXTUAL COMBINATIONS
    # ======================================================

    # Brand impersonation + credential request.

    has_brand = any(
        key.startswith("brand_impersonation_")
        for key in indicators
    )

    has_credentials = any(
        key.startswith("credential_theft_")
        for key in indicators
    )

    if has_brand and has_credentials:

        _add_indicator(
            indicators,
            "brand_credential_combination",
            20,
            "Brand impersonation is combined with a request for sensitive information."
        )

    # Threat + verification.

    has_threat = any(
        key.startswith("social_engineering_")
        for key in indicators
    )

    has_verification = "account_verification" in indicators

    if has_threat and has_verification:

        _add_indicator(
            indicators,
            "threat_verification_combination",
            12,
            "Account verification is combined with threatening or pressure-based language."
        )

    # Suspicious URL + sensitive information request.

    if "risky_email_url" in indicators and has_credentials:

        _add_indicator(
            indicators,
            "url_credential_combination",
            20,
            "A suspicious link is combined with a request for sensitive information."
        )

    # Financial fraud + urgency.

    has_financial = any(
        key.startswith("financial_fraud_")
        for key in indicators
    )

    if has_financial and has_threat:

        _add_indicator(
            indicators,
            "financial_pressure_combination",
            12,
            "Financial instructions are combined with pressure or threatening language."
        )

    # ======================================================
    # 12. FINAL SCORE
    # ======================================================

    score = _calculate_score(indicators)

    reasons = [
        item["reason"]
        for item in indicators.values()
        if item["reason"]
    ]

    # ======================================================
    # 13. RETURN RESULT
    # ======================================================

    return _classify(
        score,
        reasons
    )
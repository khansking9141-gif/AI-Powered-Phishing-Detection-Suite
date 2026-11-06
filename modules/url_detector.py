import re
import ipaddress
import unicodedata

from urllib.parse import (
    urlsplit,
    unquote,
    parse_qs
)


# ==========================================================
# CONFIGURATION
# ==========================================================

SAFE_THRESHOLD = 30
SUSPICIOUS_THRESHOLD = 70

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at"
}


# Known brands and their official domains.
# This is a limited list, not a complete brand database.

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
    "twitter": ["x.com", "twitter.com"],
    "telegram": ["telegram.org"],
    "spotify": ["spotify.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "discord": ["discord.com"],
    "wikipedia": ["wikipedia.org"]
}


SENSITIVE_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "password",
    "credential",
    "authenticate",
    "authentication",
    "account",
    "banking",
    "wallet",
    "payment",
    "secure",
    "security",
    "confirm",
    "recover",
    "unlock",
    "suspended",
    "restore",
    "update",
    "validate",
    "identity"
}


HIGH_RISK_KEYWORDS = {
    "steal",
    "phish",
    "otp",
    "credential",
    "password",
    "seedphrase",
    "seed-phrase",
    "privatekey",
    "private-key",
    "collect-payment",
    "free-gift",
    "claim-prize",
    "refund-claim"
}


SUSPICIOUS_QUERY_KEYS = {
    "redirect",
    "redirect_url",
    "return",
    "return_url",
    "continue",
    "next",
    "url",
    "target",
    "destination",
    "token",
    "session",
    "auth",
    "password",
    "credential",
    "otp"
}


def add_reason(reasons, message):
    if message not in reasons:
        reasons.append(message)


def normalize_hostname(hostname):

    hostname = hostname.lower().rstrip(".")

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        pass

    return hostname


def get_domain_labels(hostname):

    return hostname.lower().split(".")


def get_registered_domain(hostname):

    """
    Approximate registrable domain extraction.

    A complete implementation should use a maintained
    Public Suffix List database.
    """

    parts = get_domain_labels(hostname)

    if len(parts) <= 2:
        return hostname

    common_two_part_suffixes = {
        "co.in",
        "com.au",
        "co.uk",
        "com.br",
        "co.nz",
        "co.jp",
        "com.sg",
        "com.cn",
        "org.uk",
        "net.au"
    }

    last_two = ".".join(parts[-2:])

    if last_two in common_two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def contains_keyword(text, keywords):

    found = []

    text = text.lower()

    for keyword in keywords:

        pattern = (
            r"(?<![a-z0-9])"
            + re.escape(keyword)
            + r"(?![a-z0-9])"
        )

        if re.search(pattern, text):
            found.append(keyword)

    return found


def analyze_url(url):

    """
    PhishGuard URL Detection Engine.

    Returns:

        {
            "risk_score": int,
            "risk_level": str,
            "reasons": list
        }

    Classification:

        0-30   : Safe
        31-69  : Suspicious
        70-100 : Phishing

    This is a heuristic detector, not a guarantee that
    every phishing URL will be detected.
    """

    risk_score = 0
    reasons = []

    # ======================================================
    # 1. INPUT VALIDATION
    # ======================================================

    if not isinstance(url, str) or not url.strip():

        return {
            "risk_score": 0,
            "risk_level": "Invalid",
            "reasons": ["No valid URL was provided."]
        }

    original_url = url.strip()

    if len(original_url) > 4096:

        return {
            "risk_score": 100,
            "risk_level": "Phishing",
            "reasons": ["URL exceeds the maximum permitted length."]
        }

    if re.search(r"[\s\x00-\x1f\x7f]", original_url):

        return {
            "risk_score": 100,
            "risk_level": "Invalid",
            "reasons": ["URL contains invalid whitespace or control characters."]
        }

    # ======================================================
    # 2. SCHEME NORMALIZATION
    # ======================================================

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", original_url):

        original_url = "https://" + original_url

    try:

        parsed = urlsplit(original_url)

        scheme = parsed.scheme.lower()

        if scheme not in ("http", "https"):

            raise ValueError("Unsupported URL scheme")

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("Missing hostname")

        port = parsed.port

        if port is not None and not (1 <= port <= 65535):
            raise ValueError("Invalid port")

        hostname = normalize_hostname(hostname)

        if not hostname:
            raise ValueError("Invalid hostname")

    except (ValueError, TypeError):

        return {
            "risk_score": 100,
            "risk_level": "Invalid",
            "reasons": ["The URL is malformed or invalid."]
        }

    # ======================================================
    # 3. HOSTNAME VALIDATION
    # ======================================================

    try:

        ipaddress.ip_address(hostname)

        is_ip = True

    except ValueError:

        is_ip = False

    if not is_ip:

        labels = hostname.split(".")

        if (
            len(hostname) > 253
            or len(labels) < 2
            or any(
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r"[a-z0-9-]+",
                    label
                )
                or label.startswith("-")
                or label.endswith("-")
                for label in labels
            )
        ):

            return {
                "risk_score": 100,
                "risk_level": "Invalid",
                "reasons": ["The hostname has an invalid domain structure."]
            }

    # ======================================================
    # 4. IP ADDRESS DETECTION
    # ======================================================

    if is_ip:

        risk_score += 30

        add_reason(
            reasons,
            "The URL uses an IP address instead of a domain name."
        )

    # ======================================================
    # 5. URL LENGTH ANALYSIS
    # ======================================================

    if len(original_url) > 100:

        risk_score += 8

        add_reason(
            reasons,
            "The URL is unusually long."
        )

    if len(original_url) > 200:

        risk_score += 7

        add_reason(
            reasons,
            "The URL contains an excessively long address."
        )

    # ======================================================
    # 6. USERNAME AND PASSWORD IN URL
    # ======================================================

    if parsed.username is not None or parsed.password is not None:

        risk_score += 30

        add_reason(
            reasons,
            "The URL contains embedded username or password information."
        )

    # ======================================================
    # 7. @ SYMBOL DETECTION
    # ======================================================

    if "@" in parsed.netloc:

        risk_score += 25

        add_reason(
            reasons,
            "The URL contains an @ symbol that may disguise its actual destination."
        )

    # ======================================================
    # 8. HTTP SECURITY CHECK
    # ======================================================

    if scheme == "http":

        risk_score += 8

        add_reason(
            reasons,
            "The URL uses unencrypted HTTP."
        )

    # ======================================================
    # 9. SUSPICIOUS PORT DETECTION
    # ======================================================

    if port is not None and port not in (80, 443):

        risk_score += 10

        add_reason(
            reasons,
            "The URL uses a non-standard web port."
        )

    # ======================================================
    # 10. SUBDOMAIN ANALYSIS
    # ======================================================

    labels = get_domain_labels(hostname)

    if len(labels) >= 5:

        risk_score += 12

        add_reason(
            reasons,
            "The hostname contains an unusually large number of domain levels."
        )

    elif len(labels) == 4:

        risk_score += 5

        add_reason(
            reasons,
            "The hostname contains multiple subdomains."
        )

    # ======================================================
    # 11. HYPHEN ANALYSIS
    # ======================================================

    hyphen_count = hostname.count("-")

    if hyphen_count >= 4:

        risk_score += 12

        add_reason(
            reasons,
            "The hostname contains an unusually high number of hyphens."
        )

    elif hyphen_count >= 2:

        risk_score += 5

        add_reason(
            reasons,
            "The hostname contains multiple hyphens."
        )

    # ======================================================
    # 12. PUNYCODE DETECTION
    # ======================================================

    if "xn--" in hostname:

        risk_score += 20

        add_reason(
            reasons,
            "The hostname contains Punycode encoding and requires inspection."
        )

    # ======================================================
    # 13. UNICODE DETECTION
    # ======================================================

    if any(
        ord(character) > 127
        for character in parsed.netloc
    ):

        risk_score += 15

        add_reason(
            reasons,
            "The URL contains non-ASCII characters that may imitate legitimate domains."
        )

    # ======================================================
    # 14. URL SHORTENER DETECTION
    # ======================================================

    if hostname in SHORTENERS:

        risk_score += 20

        add_reason(
            reasons,
            "The URL uses a shortening service that hides the final destination."
        )

    # ======================================================
    # 15. BRAND IMPERSONATION DETECTION
    # ======================================================

    registered_domain = get_registered_domain(hostname)

    brand_found = []

    for brand, official_domains in BRANDS.items():

        if brand not in hostname:
            continue

        legitimate_domain = any(
            hostname == domain
            or hostname.endswith("." + domain)
            for domain in official_domains
        )

        if not legitimate_domain:

            brand_found.append(brand)

    if brand_found:

        risk_score += 40

        add_reason(
            reasons,
            "Possible brand impersonation detected: "
            + ", ".join(brand_found)
        )

    # ======================================================
    # 16. SUSPICIOUS KEYWORD ANALYSIS
    # ======================================================

    decoded_path = unquote(parsed.path)

    inspected_text = (
        hostname
        + " "
        + decoded_path
        + " "
        + parsed.query
    ).lower()

    found_keywords = contains_keyword(
        inspected_text,
        SENSITIVE_KEYWORDS
    )

    if found_keywords:

        keyword_score = min(
            len(found_keywords) * 4,
            16
        )

        risk_score += keyword_score

        add_reason(
            reasons,
            "Sensitive URL keywords detected: "
            + ", ".join(found_keywords)
        )

    # ======================================================
    # 17. HIGH-RISK KEYWORD ANALYSIS
    # ======================================================

    high_risk_found = contains_keyword(
        inspected_text,
        HIGH_RISK_KEYWORDS
    )

    if high_risk_found:

        risk_score += min(
            len(high_risk_found) * 12,
            24
        )

        add_reason(
            reasons,
            "High-risk phishing-related terms detected: "
            + ", ".join(high_risk_found)
        )

    # ======================================================
    # 18. SUSPICIOUS QUERY PARAMETERS
    # ======================================================

    try:

        query_parameters = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        suspicious_parameters = [
            key
            for key in query_parameters
            if key.lower() in SUSPICIOUS_QUERY_KEYS
        ]

        if suspicious_parameters:

            risk_score += min(
                len(suspicious_parameters) * 5,
                15
            )

            add_reason(
                reasons,
                "Potentially sensitive query parameters detected: "
                + ", ".join(suspicious_parameters)
            )

    except ValueError:

        risk_score += 5

        add_reason(
            reasons,
            "The URL contains unusual query parameter formatting."
        )

    # ======================================================
    # 19. ENCODING ANALYSIS
    # ======================================================

    if re.search(
        r"%[0-9a-fA-F]{2}",
        original_url
    ):

        decoded_url = unquote(original_url)

        if (
            "../" in decoded_url
            or "..\\" in decoded_url
            or "\\" in decoded_url
            or "%00" in original_url.lower()
        ):

            risk_score += 15

            add_reason(
                reasons,
                "The URL contains encoded traversal or unusual path characters."
            )

        else:

            risk_score += 3

            add_reason(
                reasons,
                "The URL contains percent-encoded characters."
            )

    # ======================================================
    # 20. REPEATED SUSPICIOUS WORDS
    # ======================================================

    combined_path = (
        hostname + "/" + decoded_path
    ).lower()

    repeated_patterns = [
        r"login.{0,30}login",
        r"verify.{0,30}account",
        r"secure.{0,30}login",
        r"password.{0,30}verify",
        r"account.{0,30}restore"
    ]

    for pattern in repeated_patterns:

        if re.search(pattern, combined_path):

            risk_score += 10

            add_reason(
                reasons,
                "The URL contains repeated or combined sensitive actions."
            )

            break

    # ======================================================
    # 21. URL REDIRECT ANALYSIS
    # ======================================================

    redirect_parameters = {
        "redirect",
        "redirect_url",
        "return_url",
        "next",
        "continue",
        "destination",
        "target"
    }

    for key, values in query_parameters.items() if 'query_parameters' in locals() else []:

        if key.lower() not in redirect_parameters:
            continue

        for value in values:

            destination = unquote(value).strip()

            if (
                destination.startswith("http://")
                or destination.startswith("https://")
                or destination.startswith("//")
            ):

                try:

                    destination_host = urlsplit(
                        destination if not destination.startswith("//")
                        else "https:" + destination
                    ).hostname

                    if (
                        destination_host
                        and destination_host.lower() != hostname
                    ):

                        risk_score += 15

                        add_reason(
                            reasons,
                            "The URL contains a redirect to a different domain."
                        )

                except ValueError:

                    risk_score += 10

                break

    # ======================================================
    # 22. COMBINATION-BASED DETECTION
    # ======================================================

    # Brand impersonation combined with sensitive actions.

    if brand_found and found_keywords:

        risk_score += 20

        add_reason(
            reasons,
            "Brand impersonation is combined with account or security-related actions."
        )

    # High-risk terms combined with credential-related terms.

    if high_risk_found and found_keywords:

        risk_score += 15

        add_reason(
            reasons,
            "High-risk terms appear alongside sensitive account-related actions."
        )

    # An IP address combined with sensitive account actions.

    if is_ip and found_keywords:

        risk_score += 15

        add_reason(
            reasons,
            "An IP-based URL contains sensitive account-related actions."
        )

    # ======================================================
    # 23. FINAL SCORE
    # ======================================================

    risk_score = max(
        0,
        min(int(risk_score), 100)
    )

    # ======================================================
    # 24. RISK CLASSIFICATION
    # ======================================================

    if risk_score >= SUSPICIOUS_THRESHOLD:

        risk_level = "Phishing"

    elif risk_score > SAFE_THRESHOLD:

        risk_level = "Suspicious"

    else:

        risk_level = "Safe"

    # ======================================================
    # 25. DEFAULT REASON
    # ======================================================

    if not reasons:

        reasons.append(
            "No significant phishing indicators were detected by the rule-based analysis."
        )

    # ======================================================
    # 26. RETURN RESULT
    # ======================================================

    return {

        "risk_score": risk_score,

        "risk_level": risk_level,

        "reasons": reasons

    }
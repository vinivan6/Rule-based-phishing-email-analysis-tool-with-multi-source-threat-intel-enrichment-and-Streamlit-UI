import re
from typing import List, Tuple, Optional
from app.services.email_parser import extract_urls, normalize_headers, detect_attachment_risks


URGENT_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\baction required\b",
    r"\bverify now\b",
    r"\baccount will be suspended\b",
    r"\bmailbox will be disabled\b",
    r"\bfinal warning\b"
]

CREDENTIAL_PATTERNS = [
    r"\bverify your password\b",
    r"\bconfirm your account\b",
    r"\blogin to continue\b",
    r"\breset your password\b",
    r"\bupdate your credentials\b",
    r"\bsign in now\b"
]

GENERIC_GREETING_PATTERNS = [
    r"\bdear user\b",
    r"\bdear customer\b",
    r"\bvalued customer\b",
    r"\bdear account holder\b"
]

SUSPICIOUS_DOMAIN_PATTERNS = [
    r"micr0soft",
    r"paypa1",
    r"g00gle",
    r"arnazon",
    r"secure-login",
    r"account-verify",
    r"support-update"
]

SUSPICIOUS_URL_PATTERNS = [
    r"login",
    r"verify",
    r"reset",
    r"secure",
    r"account",
    r"update"
]

def find_pattern_matches(text: str, patterns: List[str]) -> List[str]:
    matches = []
    lowered_text = text.lower()

    for pattern in patterns:
        if re.search(pattern, lowered_text):
            matches.append(pattern)

    return matches


def analyze_email_rules(
    sender: str, subject: str, body: str,
    headers: Optional[str] = None, attachments: Optional[List[str]] = None
 ) -> Tuple[str, str, List[str], List[str], str]:
    reasons = []
    indicators = []

    combined_text = f"{subject}\n{body}".lower()
    sender_lower = sender.lower()

    urgent_matches = find_pattern_matches(combined_text, URGENT_PATTERNS)
    if urgent_matches:
        reasons.append("The email uses urgent or pressure-based language.")
        indicators.append("urgency")

    credential_matches = find_pattern_matches(combined_text, CREDENTIAL_PATTERNS)
    if credential_matches:
        reasons.append("The email asks the recipient to verify, update, or enter credentials.")
        indicators.append("credential_request")

    greeting_matches = find_pattern_matches(combined_text, GENERIC_GREETING_PATTERNS)
    if greeting_matches:
        reasons.append("The email uses a generic greeting instead of addressing the recipient directly.")
        indicators.append("generic_greeting")

    domain_matches = find_pattern_matches(sender_lower, SUSPICIOUS_DOMAIN_PATTERNS)
    if domain_matches:
        reasons.append("The sender address appears to use a lookalike or suspicious domain pattern.")
        indicators.append("lookalike_domain")

    urls = extract_urls(body)
    if urls:
        lowered_urls = " ".join(urls).lower()
        suspicious_url_matches = find_pattern_matches(lowered_urls, SUSPICIOUS_URL_PATTERNS)
        if suspicious_url_matches:
            reasons.append("The email contains links with potentially suspicious account or verification terms.")
            indicators.append("suspicious_url")

    parsed_headers = normalize_headers(headers)
    if "reply-to" in parsed_headers and parsed_headers.get("reply-to", "").lower() != sender_lower:
        reasons.append("The Reply-To header does not match the sender address.")
        indicators.append("reply_to_mismatch")

    risky_attachments = detect_attachment_risks(attachments)
    if risky_attachments:
        reasons.append("The email includes attachments with file types that are commonly abused in phishing attacks.")
        indicators.append("risky_attachment")

    if len(indicators) >= 3:
        verdict = "phishing"
        confidence = "high"
    elif len(indicators) == 2:
        verdict = "suspicious"
        confidence = "medium"
    elif len(indicators) == 1:
        verdict = "suspicious"
        confidence = "low"
    else:
        verdict = "likely_safe"
        confidence = "medium"
        reasons.append("No strong phishing indicators were detected by the rule-based checks.")
        indicators.append("no_strong_indicators")

    if "risky_attachment" in indicators and verdict in {"phishing", "suspicious"}:
        recommended_action = "Do not click links, open attachments, or reply. Report the email to the security team."
    elif verdict == "phishing":
        recommended_action = "Do not click links, open attachments, or reply. Report the email to the security team."
    elif verdict == "suspicious":
        recommended_action = "Treat the email with caution and verify the sender through a trusted channel."
    else:
        recommended_action = "No immediate phishing indicators detected, but continue normal caution."

    return verdict, confidence, reasons, indicators, recommended_action
import re
from typing import Dict, List, Tuple, Optional
from app.services.email_parser import (
    extract_urls,
    detect_attachment_risks,
    extract_authentication_results,
    extract_return_path,
    count_received_headers,
    extract_reply_to,
    extract_ip_addresses,
    extract_message_id,
    extract_phone_numbers,
    extract_amounts,
    extract_domain_from_url,
)


URGENT_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\baction required\b",
    r"\bverify now\b",
    r"\baccount will be suspended\b",
    r"\bmailbox will be disabled\b",
    r"\bfinal warning\b",
]

CREDENTIAL_PATTERNS = [
    r"\bverify your password\b",
    r"\bconfirm your account\b",
    r"\blogin to continue\b",
    r"\breset your password\b",
    r"\bupdate your credentials\b",
    r"\bsign in now\b",
]

GENERIC_GREETING_PATTERNS = [
    r"\bdear user\b",
    r"\bdear customer\b",
    r"\bvalued customer\b",
    r"\bdear account holder\b",
]

SUSPICIOUS_DOMAIN_PATTERNS = [
    r"micr0soft",
    r"paypa1",
    r"g00gle",
    r"arnazon",
    r"secure-login",
    r"account-verify",
    r"support-update",
]

SUSPICIOUS_URL_PATTERNS = [
    r"login",
    r"verify",
    r"reset",
    r"secure",
    r"account",
    r"update",
]

TRUSTED_BRANDS = [
    "microsoft",
    "google",
    "paypal",
    "amazon",
    "apple",
    "outlook",
    "gmail",
]

FINANCIAL_CONTEXT_PATTERNS = [
    r"\bpending deposit\b",
    r"\bmoney received\b",
    r"\baccept money\b",
    r"\btransfer to a bank\b",
    r"\bpayment pending\b",
    r"\bpayout\b",
    r"\bclaim funds\b",
    r"\baccount activation\b",
]

FINANCIAL_ACTION_BAIT_PATTERNS = [
    r"\bget instant access\b",
    r"\baccept money\b",
    r"\bclaim now\b",
    r"\bactivate\b",
    r"\btransfer now\b",
]

THREAT_PATTERNS = [
    r"\bsuspension\b",
    r"\bviolation\b",
    r"\blegal action\b",
    r"\bdisabled\b",
    r"\brestricted\b",
]

CALLBACK_PATTERNS = [
    r"\bcall\b",
    r"\bcontact support\b",
    r"\bquestions\?\s*call\b",
]

LOOKALIKE_REPLACEMENTS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "rn": "m",
}


def find_pattern_matches(text: str, patterns: List[str]) -> List[str]:
    matches = []
    lowered_text = text.lower()

    for pattern in patterns:
        if re.search(pattern, lowered_text):
            matches.append(pattern)

    return matches


def domain_from_email(value: Optional[str]) -> Optional[str]:
    if not value or "@" not in value:
        return None
    return value.split("@")[-1].strip().lower()


def domain_from_message_id(message_id: Optional[str]) -> Optional[str]:
    if not message_id or "@" not in message_id:
        return None
    return message_id.split("@")[-1].strip().lower()


def find_brands_in_text(text: str) -> List[str]:
    if not text:
        return []

    lowered = text.lower()
    found = []

    for brand in TRUSTED_BRANDS:
        if brand in lowered:
            found.append(brand)

    return found


def count_subdomains(domain: str) -> int:
    return domain.count(".")


def looks_like_ip_domain(domain: str) -> bool:
    return re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", domain or "") is not None


def normalize_lookalikes(text: str) -> str:
    normalized = text.lower()
    for old, new in LOOKALIKE_REPLACEMENTS.items():
        normalized = normalized.replace(old, new)
    return normalized


def detect_lookalike_brand_in_domain(domain: Optional[str]) -> bool:
    if not domain:
        return False

    normalized = normalize_lookalikes(domain)
    for brand in TRUSTED_BRANDS:
        if brand in normalized and brand not in domain.lower():
            return True
    return False


def extract_currency_tokens(amounts: List[str]) -> List[str]:
    tokens = []
    for amount in amounts:
        upper_amount = amount.upper()
        if "USD" in upper_amount or "$" in amount:
            tokens.append("USD")
        elif "PHP" in upper_amount or "₱" in amount:
            tokens.append("PHP")
        elif "EUR" in upper_amount or "€" in amount:
            tokens.append("EUR")
        elif "GBP" in upper_amount or "£" in amount:
            tokens.append("GBP")
        elif "INR" in upper_amount or "₹" in amount:
            tokens.append("INR")
    return tokens


def score_indicator(indicators: List[str]) -> int:
    weights: Dict[str, int] = {
        "financial_context": 1,
        "urgency": 1,
        "generic_greeting": 1,
        "long_url": 1,
        "many_subdomains": 1,
        "hyphenated_domain": 1,
        "financial_action_bait": 2,
        "callback_phishing": 2,
        "suspicious_url": 2,
        "credential_request": 2,
        "brand_impersonation": 2,
        "display_name_spoofing": 2,
        "lookalike_domain": 2,
        "lookalike_url_domain": 2,
        "amount_mismatch": 3,
        "currency_mismatch": 3,
        "reply_to_mismatch": 3,
        "spf_fail": 3,
        "dkim_fail": 3,
        "dmarc_fail": 3,
        "return_path_mismatch": 3,
        "message_id_mismatch": 3,
        "risky_attachment": 3,
        "ip_in_url": 3,
    }

    return sum(weights.get(indicator, 1) for indicator in indicators)


def analyze_email_rules(
    sender: str,
    display_name: Optional[str] = None,
    subject: str = "",
    body: str = "",
    headers: Optional[str] = None,
    attachments: Optional[List[str]] = None
) -> Tuple[str, str, List[str], List[str], str]:
    reasons = []
    indicators = []

    combined_text = f"{subject}\n{body}".lower()
    sender_lower = sender.lower()
    display_name_lower = (display_name or "").lower()

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

    financial_context_matches = find_pattern_matches(combined_text, FINANCIAL_CONTEXT_PATTERNS)
    if financial_context_matches:
        reasons.append("The email contains financial transaction or payout language.")
        indicators.append("financial_context")

    financial_action_matches = find_pattern_matches(combined_text, FINANCIAL_ACTION_BAIT_PATTERNS)
    if financial_action_matches:
        reasons.append("The email pushes immediate financial action or activation behavior.")
        indicators.append("financial_action_bait")

    threat_matches = find_pattern_matches(combined_text, THREAT_PATTERNS)
    if threat_matches:
        reasons.append("The email uses threat-oriented or fear-inducing language.")
        indicators.append("urgency")

    phone_numbers = extract_phone_numbers(f"{subject}\n{body}")
    callback_matches = find_pattern_matches(combined_text, CALLBACK_PATTERNS)
    if phone_numbers and callback_matches and financial_context_matches:
        reasons.append("The email combines money-related messaging with a callback phone number.")
        indicators.append("callback_phishing")

    urls = extract_urls(body)
    if urls:
        lowered_urls = " ".join(urls).lower()
        suspicious_url_matches = find_pattern_matches(lowered_urls, SUSPICIOUS_URL_PATTERNS)
        if suspicious_url_matches:
            reasons.append("The email contains links with potentially suspicious account or verification terms.")
            indicators.append("suspicious_url")

        for url in urls:
            if len(url) > 75 and "long_url" not in indicators:
                reasons.append("The email contains an unusually long URL.")
                indicators.append("long_url")

            url_domain = extract_domain_from_url(url)
            if url_domain:
                if count_subdomains(url_domain) > 3 and "many_subdomains" not in indicators:
                    reasons.append("The email contains a URL with a high number of subdomains.")
                    indicators.append("many_subdomains")

                if "-" in url_domain and "hyphenated_domain" not in indicators:
                    reasons.append("The email contains a hyphenated domain, which is common in lookalike infrastructure.")
                    indicators.append("hyphenated_domain")

                if looks_like_ip_domain(url_domain) and "ip_in_url" not in indicators:
                    reasons.append("The email contains a URL that uses a raw IP address instead of a named domain.")
                    indicators.append("ip_in_url")

                if detect_lookalike_brand_in_domain(url_domain) and "lookalike_url_domain" not in indicators:
                    reasons.append("The email contains a URL domain that appears to mimic a trusted brand.")
                    indicators.append("lookalike_url_domain")

    reply_to = extract_reply_to(headers)
    if reply_to and reply_to.lower() != sender_lower:
        reasons.append("The Reply-To header does not match the sender address.")
        indicators.append("reply_to_mismatch")

    auth_results = extract_authentication_results(headers)
    if auth_results.get("spf") == "fail":
        reasons.append("SPF authentication failed.")
        indicators.append("spf_fail")

    if auth_results.get("dkim") == "fail":
        reasons.append("DKIM authentication failed.")
        indicators.append("dkim_fail")

    if auth_results.get("dmarc") == "fail":
        reasons.append("DMARC authentication failed.")
        indicators.append("dmarc_fail")

    return_path = extract_return_path(headers)
    sender_domain = domain_from_email(sender)
    return_path_domain = domain_from_email(return_path)

    if return_path and sender_domain and return_path_domain and sender_domain != return_path_domain:
        reasons.append("The Return-Path domain does not match the sender domain.")
        indicators.append("return_path_mismatch")

    message_id = extract_message_id(headers)
    message_id_domain = domain_from_message_id(message_id)
    if message_id and sender_domain and message_id_domain and sender_domain != message_id_domain:
        reasons.append("The Message-ID domain does not match the sender domain.")
        indicators.append("message_id_mismatch")

    received_count = count_received_headers(headers)
    if received_count >= 5:
        reasons.append("The email passed through a high number of mail hops.")
        indicators.append("many_mail_hops")

    risky_attachments = detect_attachment_risks(attachments)
    if risky_attachments:
        reasons.append("The email includes attachments with file types that are commonly abused in phishing attacks.")
        indicators.append("risky_attachment")

    ip_addresses = extract_ip_addresses(headers)
    if ip_addresses:
        unique_ips = sorted(set(ip_addresses))
        if len(unique_ips) >= 3:
            reasons.append("Multiple IP addresses were observed in the email headers.")
            indicators.append("multiple_header_ips")

    mentioned_brands = find_brands_in_text(f"{display_name_lower}\n{subject}\n{body}")
    if mentioned_brands and sender_domain:
        suspicious_brand_use = True
        for brand in mentioned_brands:
            if brand in sender_domain:
                suspicious_brand_use = False
                break

        if suspicious_brand_use:
            reasons.append("The email references a known brand, but the sender domain does not align with that brand.")
            indicators.append("brand_impersonation")

    if display_name_lower and sender_domain:
        if "microsoft" in display_name_lower and "microsoft" not in sender_domain:
            reasons.append("The display name suggests Microsoft, but the sender domain does not match.")
            indicators.append("display_name_spoofing")
        elif "google" in display_name_lower and "google" not in sender_domain:
            reasons.append("The display name suggests Google, but the sender domain does not match.")
            indicators.append("display_name_spoofing")
        elif "paypal" in display_name_lower and "paypal" not in sender_domain:
            reasons.append("The display name suggests PayPal, but the sender domain does not match.")
            indicators.append("display_name_spoofing")
        elif "amazon" in display_name_lower and "amazon" not in sender_domain:
            reasons.append("The display name suggests Amazon, but the sender domain does not match.")
            indicators.append("display_name_spoofing")
        elif "apple" in display_name_lower and "apple" not in sender_domain:
            reasons.append("The display name suggests Apple, but the sender domain does not match.")
            indicators.append("display_name_spoofing")

    all_amounts = extract_amounts(f"{subject}\n{body}\n{' '.join(urls)}")
    unique_amounts = sorted(set(all_amounts))
    if len(unique_amounts) >= 2:
        reasons.append("The email contains multiple inconsistent monetary amounts.")
        indicators.append("amount_mismatch")

    currency_tokens = sorted(set(extract_currency_tokens(all_amounts)))
    if len(currency_tokens) >= 2:
        reasons.append("The email mixes multiple currencies in a suspicious way.")
        indicators.append("currency_mismatch")

    score = score_indicator(indicators)

    if score >= 8:
        verdict = "phishing"
        confidence = "high"
    elif score >= 4:
        verdict = "suspicious"
        confidence = "medium"
    elif score >= 1:
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
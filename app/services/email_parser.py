import re
import ipaddress
from typing import Dict, List, Optional
from urllib.parse import urlparse
from email.utils import parseaddr


URL_PATTERN = r"https?://[^\s]+"

SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".bat",
    ".cmd",
    ".zip",
    ".html",
    ".htm",
    ".iso"
}

PHONE_PATTERN = r"(?:\+?\d{1,2}[\s\-]?)?(?:\(?\d{3}\)?[\s\-]?)\d{3}[\s\-]?\d{4}"
AMOUNT_PATTERN = r"(?:USD|EUR|GBP|CAD|AUD|INR|PHP|\$|€|£|₹|₱)\s?\d+(?:[.,]\d{1,2})?"
IPV4_CANDIDATE_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(URL_PATTERN, text)


def normalize_headers(headers: Optional[str]) -> Dict[str, str]:
    if not headers:
        return {}

    parsed_headers = {}

    for line in headers.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            parsed_headers[key.strip().lower()] = value.strip()

    return parsed_headers


def detect_attachment_risks(attachments: Optional[List[str]]) -> List[str]:
    if not attachments:
        return []

    risky_attachments = []

    for filename in attachments:
        lower_name = filename.lower()
        for ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            if lower_name.endswith(ext):
                risky_attachments.append(filename)
                break

    return risky_attachments


def extract_authentication_results(headers: Optional[str]) -> Dict[str, str]:
    if not headers:
        return {}

    results = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown"
    }

    lower_headers = headers.lower()

    spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none)", lower_headers)
    dkim_match = re.search(r"dkim=(pass|fail|none|neutral)", lower_headers)
    dmarc_match = re.search(r"dmarc=(pass|fail|none)", lower_headers)

    if spf_match:
        results["spf"] = spf_match.group(1)

    if dkim_match:
        results["dkim"] = dkim_match.group(1)

    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1)

    return results


def extract_return_path(headers: Optional[str]) -> Optional[str]:
    if not headers:
        return None

    match = re.search(r"^return-path:\s*<([^>]+)>", headers, re.IGNORECASE | re.MULTILINE)
    if match:
        return match.group(1).strip()

    return None


def count_received_headers(headers: Optional[str]) -> int:
    if not headers:
        return 0

    matches = re.findall(r"^received:", headers, re.IGNORECASE | re.MULTILINE)
    return len(matches)


def extract_reply_to(headers: Optional[str]) -> Optional[str]:
    if not headers:
        return None

    match = re.search(r"^reply-to:\s*(.+)$", headers, re.IGNORECASE | re.MULTILINE)
    if match:
        return match.group(1).strip()

    return None


def _extract_valid_ipv4s(text: str) -> List[str]:
    valid_ips: List[str] = []

    for candidate in IPV4_CANDIDATE_PATTERN.findall(text):
        try:
            ip_obj = ipaddress.ip_address(candidate)

            if ip_obj.version != 4:
                continue

            if (
                ip_obj.is_loopback
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                continue

            if candidate not in valid_ips:
                valid_ips.append(candidate)

        except ValueError:
            continue

    return valid_ips


def extract_ip_addresses(headers: Optional[str]) -> List[str]:
    if not headers:
        return []

    relevant_lines = []
    for line in headers.splitlines():
        lower_line = line.lower().strip()
        if (
            lower_line.startswith("received:")
            or lower_line.startswith("x-originating-ip:")
            or lower_line.startswith("x-forwarded-for:")
        ):
            relevant_lines.append(line)

    if not relevant_lines:
        return []

    return _extract_valid_ipv4s("\n".join(relevant_lines))

def extract_domain_from_email(email_address: Optional[str]) -> str:
    if not email_address:
        return ""

    _, parsed_email = parseaddr(email_address)

    if "@" not in parsed_email:
        return ""

    return parsed_email.split("@")[-1].strip().lower()


def get_organizational_domain(domain: str) -> str:
    if not domain:
        return ""

    parts = domain.lower().split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return domain.lower()


def domains_align(domain_a: str, domain_b: str) -> bool:
    if not domain_a or not domain_b:
        return False

    return get_organizational_domain(domain_a) == get_organizational_domain(domain_b)


def extract_header_domain(headers: Optional[str], header_name: str) -> str:
    if not headers:
        return ""

    pattern = rf"^{header_name}:\s*(.+)$"

    for line in headers.splitlines():
        match = re.match(pattern, line, re.IGNORECASE)
        if match:
            return extract_domain_from_email(match.group(1))

    return ""


def extract_dkim_domain(headers: Optional[str]) -> str:
    if not headers:
        return ""

    match = re.search(r"dkim=pass.*?header\.i=@([A-Za-z0-9.-]+)", headers, re.IGNORECASE)
    if match:
        return match.group(1).lower()

    match = re.search(r"\bd=([A-Za-z0-9.-]+)", headers, re.IGNORECASE)
    if match:
        return match.group(1).lower()

    return ""


def extract_spf_mailfrom_domain(headers: Optional[str]) -> str:
    if not headers:
        return ""

    match = re.search(r"smtp\.mailfrom=([A-Za-z0-9@._+-]+)", headers, re.IGNORECASE)
    if match:
        value = match.group(1).strip().lower()

        if "@" in value:
            return extract_domain_from_email(value)

        return value

    return ""


def extract_dmarc_header_from_domain(headers: Optional[str]) -> str:
    if not headers:
        return ""

    match = re.search(r"header\.from=([A-Za-z0-9.-]+)", headers, re.IGNORECASE)
    if match:
        return match.group(1).lower()

    return ""


def analyze_domain_alignment(sender: str, headers: Optional[str]) -> dict:
    from_domain = extract_domain_from_email(sender)
    reply_to_domain = extract_header_domain(headers, "Reply-To")
    return_path_domain = extract_header_domain(headers, "Return-Path")
    dkim_domain = extract_dkim_domain(headers)
    spf_mailfrom_domain = extract_spf_mailfrom_domain(headers)
    dmarc_header_from_domain = extract_dmarc_header_from_domain(headers)

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "dkim_domain": dkim_domain,
        "spf_mailfrom_domain": spf_mailfrom_domain,
        "dmarc_header_from_domain": dmarc_header_from_domain,
        "reply_to_aligned": domains_align(from_domain, reply_to_domain) if reply_to_domain else True,
        "return_path_aligned": domains_align(from_domain, return_path_domain) if return_path_domain else True,
        "dkim_aligned": domains_align(from_domain, dkim_domain) if dkim_domain else True,
        "spf_aligned": domains_align(from_domain, spf_mailfrom_domain) if spf_mailfrom_domain else True,
        "dmarc_header_from_aligned": domains_align(from_domain, dmarc_header_from_domain) if dmarc_header_from_domain else True,
    }


def extract_message_id(headers: Optional[str]) -> Optional[str]:
    if not headers:
        return None

    match = re.search(r"^message-id:\s*<([^>]+)>", headers, re.IGNORECASE | re.MULTILINE)
    if match:
        return match.group(1).strip()

    return None


def extract_phone_numbers(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(PHONE_PATTERN, text)


def extract_amounts(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(AMOUNT_PATTERN, text, re.IGNORECASE)


def extract_domain_from_url(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc.lower()
    except Exception:
        return None
    return None
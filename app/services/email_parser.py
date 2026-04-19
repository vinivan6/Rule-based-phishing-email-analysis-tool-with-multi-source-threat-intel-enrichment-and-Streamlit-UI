import re
from typing import Dict, List, Optional

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


def extract_ip_addresses(headers: Optional[str]) -> List[str]:
    if not headers:
        return []

    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", headers)
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
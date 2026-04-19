from typing import List, Optional
from urllib.parse import urlparse

from app.models.response_models import ExtractedArtifacts
from app.services.email_parser import extract_urls, extract_ip_addresses, extract_return_path


def extract_domain_from_url(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc.lower()
    except Exception:
        return None
    return None


def extract_domain_from_email(email_value: Optional[str]) -> Optional[str]:
    if not email_value or "@" not in email_value:
        return None
    return email_value.split("@")[-1].strip().lower()


def build_artifacts(
    sender: str,
    body: str,
    headers: Optional[str] = None,
    attachments: Optional[List[str]] = None
) -> ExtractedArtifacts:
    urls = extract_urls(body)
    ip_addresses = sorted(set(extract_ip_addresses(headers)))

    domains = set()

    sender_domain = extract_domain_from_email(sender)
    if sender_domain:
        domains.add(sender_domain)

    return_path = extract_return_path(headers)
    return_path_domain = extract_domain_from_email(return_path)
    if return_path_domain:
        domains.add(return_path_domain)

    for url in urls:
        url_domain = extract_domain_from_url(url)
        if url_domain:
            domains.add(url_domain)

    return ExtractedArtifacts(
        urls=urls,
        domains=sorted(domains),
        ip_addresses=ip_addresses,
        attachments=attachments or []
    )
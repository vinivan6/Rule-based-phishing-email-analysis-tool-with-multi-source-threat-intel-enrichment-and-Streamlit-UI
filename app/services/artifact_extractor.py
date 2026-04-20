from typing import List, Optional

from app.models.response_models import ExtractedArtifacts
from app.services.email_parser import (
    extract_urls,
    extract_ip_addresses,
    extract_return_path,
    extract_domain_from_url,
    extract_phone_numbers,
    extract_amounts,
)


def extract_domain_from_email(email_value: Optional[str]) -> Optional[str]:
    if not email_value or "@" not in email_value:
        return None
    return email_value.split("@")[-1].strip().lower()


def build_artifacts(
    sender: str,
    subject: str,
    body: str,
    headers: Optional[str] = None,
    attachments: Optional[List[str]] = None
) -> ExtractedArtifacts:
    urls = extract_urls(body)
    ip_addresses = sorted(set(extract_ip_addresses(headers)))
    phone_numbers = sorted(set(extract_phone_numbers(f"{subject}\n{body}")))
    amounts = sorted(set(extract_amounts(f"{subject}\n{body}")))

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
        attachments=attachments or [],
        phone_numbers=phone_numbers,
        amounts=amounts,
    )
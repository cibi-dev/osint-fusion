"""Módulo de ingesta, conectores seguros y sanitización PII."""

from osint_fusion.ingest.base import BaseConnector, validate_target_url_ssrf
from osint_fusion.ingest.cert_connector import CertTransparencyConnector
from osint_fusion.ingest.rss_connector import RSSFeedConnector
from osint_fusion.ingest.sanitizer import (
    mask_credit_cards,
    mask_internal_ips,
    mask_personal_emails,
    sanitize_document,
    sanitize_text,
)

__all__ = [
    "BaseConnector",
    "validate_target_url_ssrf",
    "RSSFeedConnector",
    "CertTransparencyConnector",
    "mask_credit_cards",
    "mask_personal_emails",
    "mask_internal_ips",
    "sanitize_text",
    "sanitize_document",
]

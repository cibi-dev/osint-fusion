"""Módulo de sanitización de información personal y sensible (PII / CWE-359)."""

from __future__ import annotations

import re

from osint_fusion.schemas import OSINTDocument

# Expresiones regulares para PII
CARD_REGEX = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")
EMAIL_REGEX = re.compile(r"\b([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b")
INTERNAL_IP_REGEX = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def mask_credit_cards(text: str) -> str:
    """Enmascara números de tarjetas de crédito o débito detectados en el texto."""
    return CARD_REGEX.sub("[CARD_MASKED]", text)


def mask_personal_emails(text: str) -> str:
    """Enmascara la parte local de correos electrónicos para proteger la privacidad."""
    def _repl(match: re.Match[str]) -> str:
        local = match.group(1)
        domain = match.group(2)
        if len(local) <= 2:
            masked_local = local[0] + "*"
        else:
            masked_local = local[0] + "***" + local[-1]
        return f"{masked_local}@{domain}"

    return EMAIL_REGEX.sub(_repl, text)


def mask_internal_ips(text: str) -> str:
    """Enmascara direcciones IPv4 privadas y loopback que revelen topología interna."""
    return INTERNAL_IP_REGEX.sub("[INTERNAL_IP]", text)


def sanitize_text(text: str) -> str:
    """Aplica todas las políticas de sanitización sobre una cadena de texto."""
    cleaned = mask_credit_cards(text)
    cleaned = mask_personal_emails(cleaned)
    cleaned = mask_internal_ips(cleaned)
    return cleaned


def sanitize_document(doc: OSINTDocument) -> OSINTDocument:
    """Crea una copia sanitizada del documento OSINTDocument con PII enmascarada."""
    return OSINTDocument(
        id=doc.id,
        source=doc.source,
        title=sanitize_text(doc.title),
        content=sanitize_text(doc.content),
        timestamp=doc.timestamp,
        metadata={
            k: (sanitize_text(v) if isinstance(v, str) else v)
            for k, v in doc.metadata.items()
        },
    )

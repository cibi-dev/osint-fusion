"""Tests unitarios de ingesta segura, blindaje anti-SSRF y sanitización PII (Fase 2.1)."""

import pytest

from osint_fusion.ingest import (
    CertTransparencyConnector,
    RSSFeedConnector,
    mask_credit_cards,
    mask_internal_ips,
    mask_personal_emails,
    sanitize_document,
    sanitize_text,
    validate_target_url_ssrf,
)
from osint_fusion.schemas import OSINTDocument


def test_validate_target_url_ssrf_blocks_private_ips():
    """Verifica que direcciones IP privadas RFC 1918 y loopback sean bloqueadas."""
    assert validate_target_url_ssrf("http://127.0.0.1/admin") is False
    assert validate_target_url_ssrf("http://10.0.0.1:8080/internal") is False
    assert validate_target_url_ssrf("https://192.168.1.50/api") is False
    assert validate_target_url_ssrf("http://172.16.0.5/secrets") is False
    assert validate_target_url_ssrf("http://169.254.169.254/latest/meta-data/") is False


def test_validate_target_url_ssrf_blocks_localhost():
    """Verifica que nombres de host locales sean rechazados."""
    assert validate_target_url_ssrf("http://localhost:8000/metrics") is False
    assert validate_target_url_ssrf("http://localhost/") is False


def test_validate_target_url_ssrf_allows_public_https():
    """Verifica que dominios públicos estándar sean permitidos."""
    assert validate_target_url_ssrf("https://www.cisa.gov/feed.xml") is True
    assert validate_target_url_ssrf("https://crt.sh/?q=test") is True


def test_validate_target_url_ssrf_rejects_non_http_schemes():
    """Verifica que esquemas no HTTP como file://, ftp:// o gopher:// sean bloqueados."""
    assert validate_target_url_ssrf("file:///etc/passwd") is False
    assert validate_target_url_ssrf("ftp://ftp.example.com/data") is False
    assert validate_target_url_ssrf("gopher://127.0.0.1:70") is False


def test_sanitizer_masks_credit_cards():
    """Verifica que números de tarjetas bancarias sean enmascarados."""
    text = "Transacción detectada con tarjeta 4111222233334444 para pago."
    cleaned = mask_credit_cards(text)
    assert "4111222233334444" not in cleaned
    assert "[CARD_MASKED]" in cleaned


def test_sanitizer_masks_personal_emails():
    """Verifica que los correos electrónicos oculten la identidad del usuario."""
    text = "Reporte enviado por juan.perez@cybercrime-threat.org en sesión."
    cleaned = mask_personal_emails(text)
    assert "juan.perez" not in cleaned
    assert "j***z@cybercrime-threat.org" in cleaned


def test_sanitizer_masks_internal_ips():
    """Verifica que direcciones IP de topología interna sean enmascaradas."""
    text = "El servidor C2 se comunicó con nodo 192.168.1.105 y gateway 10.0.1.1."
    cleaned = mask_internal_ips(text)
    assert "192.168.1.105" not in cleaned
    assert "10.0.1.1" not in cleaned
    assert "[INTERNAL_IP]" in cleaned


def test_sanitize_document_returns_sanitized_copy():
    """Verifica la sanitización integral de un objeto OSINTDocument."""
    doc = OSINTDocument(
        id="DOC-99",
        source="Threat-Dump",
        title="Alerta sobre 192.168.0.1",
        content="Contacto: admin@target.com con tarjeta 5500111122223333",
        timestamp="2026-09-14T10:00:00Z",
        metadata={"reporter": "operador@secure.com"},
    )
    clean_doc = sanitize_document(doc)

    assert "[INTERNAL_IP]" in clean_doc.title
    assert "admin@target.com" not in clean_doc.content
    assert "[CARD_MASKED]" in clean_doc.content
    assert "operador@secure.com" not in clean_doc.metadata["reporter"]


def test_rss_connector_parse_xml():
    """Verifica el parseo determinista de un feed XML RSS."""
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
        <channel>
            <title>Security Feed</title>
            <item>
                <guid>ALERT-2026-001</guid>
                <title>CISA Advisory: Ransomware Campaign</title>
                <description>Threat actors exploiting CVE-2026-1234 on edge devices.</description>
                <link>https://www.cisa.gov/advisory-001</link>
            </item>
        </channel>
    </rss>
    """
    connector = RSSFeedConnector(name="Mock-CISA", source_uri="https://www.cisa.gov/mock.xml")
    docs = connector.parse_feed_xml(sample_xml)

    assert len(docs) == 1
    assert docs[0].id == "ALERT-2026-001"
    assert "Ransomware Campaign" in docs[0].title
    assert "CVE-2026-1234" in docs[0].content


def test_rss_connector_ssrf_blocked_raises():
    """Verifica que intentar descargar desde una IP interna lance ValueError por anti-SSRF."""
    connector = RSSFeedConnector(name="Dangerous", source_uri="http://127.0.0.1:8080/feed.xml")
    with pytest.raises(ValueError, match="anti-SSRF"):
        connector.fetch_documents()


def test_cert_connector_parse_entries():
    """Verifica el procesamiento de registros de Certificate Transparency."""
    entries = [
        {
            "id": 987654,
            "common_name": "login.bank-secure-update.com",
            "name_value": "login.bank-secure-update.com\nauth.bank-secure-update.com",
            "issuer_name": "Let's Encrypt Authority X3",
        }
    ]
    connector = CertTransparencyConnector()
    docs = connector.parse_ct_entries(entries)

    assert len(docs) == 1
    assert docs[0].id == "CERT-987654"
    assert "login.bank-secure-update.com" in docs[0].title
    assert "auth.bank-secure-update.com" in docs[0].metadata["san_names"]


def test_sanitizer_idempotent_on_clean_text():
    """Verifica que la sanitización sea idempotente en texto limpio sin PII."""
    clean_text = "Standard report with no sensitive PII or private IP ranges."
    doc = OSINTDocument(
        id="clean-doc",
        source="test",
        title="Clean",
        content=clean_text,
        timestamp="2026-09-14T10:00:00Z",
    )
    sanitized = sanitize_document(doc)
    assert sanitized.content == clean_text


def test_cert_connector_empty_data():
    """Verifica que el conector maneje listas vacías sin errores."""
    connector = CertTransparencyConnector()
    assert connector.parse_ct_entries([]) == []

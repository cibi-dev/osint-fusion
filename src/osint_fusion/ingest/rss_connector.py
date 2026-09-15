"""Conector para ingesta de fuentes RSS/Atom de alertas de seguridad con protección anti-SSRF."""

from __future__ import annotations

import defusedxml.ElementTree as ET
from datetime import datetime, timezone
import uuid

import urllib.request

from osint_fusion.ingest.base import BaseConnector, validate_target_url_ssrf
from osint_fusion.schemas import OSINTDocument


class RSSFeedConnector(BaseConnector):
    """Conector seguro para fuentes RSS de vulnerabilidades y ciberamenazas (ej. CISA KEV / NVD)."""

    def __init__(
        self,
        name: str = "CISA-Alerts-Feed",
        source_uri: str = "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        timeout_seconds: float = 5.0,
    ) -> None:
        super().__init__(name=name, source_uri=source_uri)
        self.timeout_seconds = timeout_seconds

    def parse_feed_xml(self, xml_content: str) -> list[OSINTDocument]:
        """Parsea un contenido XML de feed RSS de forma segura sin resolución de entidades externas."""
        documents: list[OSINTDocument] = []
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return documents

        # Manejo de canal RSS estándar
        channel = root.find("channel")
        items = channel.findall("item") if channel is not None else root.findall(".//item")

        now_str = datetime.now(timezone.utc).isoformat()

        for item in items:
            title_node = item.find("title")
            desc_node = item.find("description")
            link_node = item.find("link")
            guid_node = item.find("guid")

            title = title_node.text.strip() if title_node is not None and title_node.text else "Sin título"
            content = desc_node.text.strip() if desc_node is not None and desc_node.text else ""
            link = link_node.text.strip() if link_node is not None and link_node.text else self.source_uri
            doc_id = guid_node.text.strip() if guid_node is not None and guid_node.text else f"RSS-{uuid.uuid4().hex[:10]}"

            documents.append(
                OSINTDocument(
                    id=doc_id,
                    source=self.name,
                    title=title,
                    content=content,
                    timestamp=now_str,
                    metadata={"link": link, "source_type": "rss"},
                )
            )

        return documents

    def fetch_documents(self) -> list[OSINTDocument]:
        """Descarga y procesa el feed RSS validando previamente la URL contra SSRF."""
        if not validate_target_url_ssrf(self.source_uri):
            raise ValueError(f"Acceso denegado a '{self.source_uri}' por política de seguridad anti-SSRF (CWE-918).")

        req = urllib.request.Request(self.source_uri, headers={"User-Agent": "OSINTFusion/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:  # nosec B310
            content = resp.read().decode("utf-8")
            return self.parse_feed_xml(content)

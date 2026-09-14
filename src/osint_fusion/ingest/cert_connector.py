"""Conector para análisis de Certificate Transparency (CT Logs) y dominios SAN."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

import httpx

from osint_fusion.ingest.base import BaseConnector, validate_target_url_ssrf
from osint_fusion.schemas import OSINTDocument


class CertTransparencyConnector(BaseConnector):
    """Conector para descubrir infraestructura ilícita y dominios SAN a partir de certificados SSL."""

    def __init__(
        self,
        name: str = "crt.sh-Query",
        source_uri: str = "https://crt.sh/?q=%.example-fraud.com&output=json",
        timeout_seconds: float = 5.0,
    ) -> None:
        super().__init__(name=name, source_uri=source_uri)
        self.timeout_seconds = timeout_seconds

    def parse_ct_entries(self, entries: list[dict[str, Any]]) -> list[OSINTDocument]:
        """Convierte una lista de entradas de CT Logs en documentos OSINT estructurados."""
        documents: list[OSINTDocument] = []
        now_str = datetime.now(timezone.utc).isoformat()

        for entry in entries:
            cert_id = str(entry.get("id", uuid.uuid4().hex[:10]))
            common_name = str(entry.get("common_name", entry.get("name_value", "unknown.domain")))
            issuer = str(entry.get("issuer_name", "Unknown CA"))
            all_names = str(entry.get("name_value", common_name)).replace("\n", ", ")

            content = (
                f"Certificado SSL detectado para dominio principal '{common_name}'. "
                f"Nombres alternativos (SAN): {all_names}. Emisor: {issuer}."
            )

            documents.append(
                OSINTDocument(
                    id=f"CERT-{cert_id}",
                    source=self.name,
                    title=f"Certificado SSL: {common_name}",
                    content=content,
                    timestamp=now_str,
                    metadata={
                        "common_name": common_name,
                        "san_names": all_names.split(", "),
                        "issuer": issuer,
                        "source_type": "certificate_transparency",
                    },
                )
            )

        return documents

    def fetch_documents(self) -> list[OSINTDocument]:
        """Consulta el log CT respetando la política de protección anti-SSRF."""
        if not validate_target_url_ssrf(self.source_uri):
            raise ValueError(f"Acceso denegado a '{self.source_uri}' por política de seguridad anti-SSRF (CWE-918).")

        with httpx.Client(timeout=self.timeout_seconds, follow_redirects=False) as client:
            resp = client.get(self.source_uri)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                return self.parse_ct_entries(data)
            return []

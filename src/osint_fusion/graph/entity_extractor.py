"""Extractor de entidades e IoCs (Indicators of Compromise) OSINT mediante expresiones regulares y validación."""

from __future__ import annotations

import ipaddress
import re
from typing import List, Optional

from osint_fusion.schemas import Entity, Relation

# Patrones Regex para IoCs y Entidades OSINT
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
ETH_WALLET_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
BTC_WALLET_REGEX = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{38,59})\b")
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|io|ru|cn|xyz|top|cc|info|biz|gov|edu|mil|ai|co|onion)\b",
    re.IGNORECASE,
)
THREAT_ACTOR_REGEX = re.compile(
    r"\b(?:APT\s?\d{1,3}|Lazarus|Fancy Bear|Cozy Bear|Sandworm|FIN\d{1,2}|Volt Typhoon|Scattered Spider)\b",
    re.IGNORECASE,
)

IGNORED_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "pdf", "txt", "doc", "docx", "zip", "tar", "gz", "py", "json", "xml", "csv"
}


class EntityExtractor:
    """Extrae entidades estructuradas e infiere relaciones a partir de texto OSINT no estructurado."""

    @staticmethod
    def _is_valid_public_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
        except ValueError:
            return False

    def extract_entities(self, text: str, doc_id: str = "") -> list[Entity]:
        """Extrae todas las entidades OSINT reconocibles en el texto.

        Args:
            text: Contenido textual no estructurado.
            doc_id: Identificador opcional del documento fuente.

        Returns:
            Lista de entidades Pydantic deduplicadas por tipo y valor.
        """
        entities: list[Entity] = []
        seen: set[tuple[str, str]] = set()

        def add_entity(etype: str, val: str, meta: Optional[dict] = None) -> None:
            key = (etype, val.lower())
            if key not in seen:
                seen.add(key)
                slug = re.sub(r"[^a-zA-Z0-9_.-]", "_", val.lower())
                entity_id = f"{etype.lower()}:{slug}"
                m = meta or {}
                if doc_id:
                    m["source_doc"] = doc_id
                entities.append(Entity(id=entity_id, type=etype, value=val, metadata=m))

        # 1. Threat Actors
        for match in THREAT_ACTOR_REGEX.finditer(text):
            add_entity("ACTOR", match.group(0).upper())

        # 2. CVEs
        for match in CVE_REGEX.finditer(text):
            add_entity("CVE", match.group(0).upper())

        # 3. Wallets Cripto (Ethereum y Bitcoin)
        for match in ETH_WALLET_REGEX.finditer(text):
            add_entity("WALLET", match.group(0).lower(), {"blockchain": "ethereum"})
        for match in BTC_WALLET_REGEX.finditer(text):
            val = match.group(0)
            if not val.startswith("0x"):  # Evitar colisión con eth
                add_entity("WALLET", val, {"blockchain": "bitcoin"})

        # 4. Hashes (Prioridad SHA256 > SHA1 > MD5 para evitar subcadenas)
        sha256_spans = []
        for match in SHA256_REGEX.finditer(text):
            sha256_spans.append(match.span())
            add_entity("HASH_SHA256", match.group(0).lower())

        for match in SHA1_REGEX.finditer(text):
            span = match.span()
            if not any(s[0] <= span[0] and span[1] <= s[1] for s in sha256_spans):
                add_entity("HASH_SHA1", match.group(0).lower())

        for match in MD5_REGEX.finditer(text):
            span = match.span()
            if not any(s[0] <= span[0] and span[1] <= s[1] for s in sha256_spans):
                add_entity("HASH_MD5", match.group(0).lower())

        # 5. Emails
        for match in EMAIL_REGEX.finditer(text):
            add_entity("EMAIL", match.group(0).lower())

        # 6. Dominios FQDN
        for match in DOMAIN_REGEX.finditer(text):
            dom = match.group(0).lower()
            ext = dom.split(".")[-1]
            if ext not in IGNORED_EXTENSIONS:
                add_entity("DOMAIN", dom)

        # 7. IPs Públicas
        for match in IPV4_REGEX.finditer(text):
            ip_str = match.group(0)
            if self._is_valid_public_ip(ip_str):
                add_entity("IP", ip_str)

        return entities

    def infer_relations(
        self, entities: list[Entity], doc_id: Optional[str] = None
    ) -> list[Relation]:
        """Infiere relaciones semánticas y de co-ocurrencia entre las entidades extraídas.

        Args:
            entities: Lista de entidades presentes en el contexto.
            doc_id: Identificador del documento si existe.

        Returns:
            Lista de objetos Relation.
        """
        relations: list[Relation] = []
        seen_edges: set[tuple[str, str]] = set()

        def add_rel(src: str, tgt: str, rel_type: str, weight: float = 1.0) -> None:
            if src == tgt:
                return
            edge = tuple(sorted([src, tgt]))
            if edge not in seen_edges:
                seen_edges.add(edge)
                relations.append(
                    Relation(source_id=src, target_id=tgt, relation_type=rel_type, weight=weight)
                )

        # Si hay un actor, asociar el actor a todos los IoCs
        actors = [e for e in entities if e.type == "ACTOR"]
        non_actors = [e for e in entities if e.type != "ACTOR"]

        if actors:
            for actor in actors:
                for target in non_actors:
                    rel_type = "USES_INFRASTRUCTURE" if target.type in ("IP", "DOMAIN") else "ASSOCIATED_WITH"
                    add_rel(actor.id, target.id, rel_type, weight=1.5)

        # Enlazar emails con sus dominios correspondientes
        emails = [e for e in entities if e.type == "EMAIL"]
        domains = [e for e in entities if e.type == "DOMAIN"]
        for em in emails:
            em_domain = em.value.split("@")[-1].lower()
            for dom in domains:
                if dom.value.lower() == em_domain:
                    add_rel(em.id, dom.id, "HOSTED_ON_DOMAIN", weight=2.0)

        # Co-ocurrencia entre entidades no conectadas (red de contexto)
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                src = entities[i]
                tgt = entities[j]
                add_rel(src.id, tgt.id, "CO_OCCURRENCE", weight=0.8)

        return relations

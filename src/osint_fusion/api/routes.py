"""Rutas y controladores de la API REST FastAPI para OSINT Fusion."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from osint_fusion.dedup.lsh_index import LSHIndex
from osint_fusion.exporters.gexf import export_to_gexf
from osint_fusion.graph.centrality import get_top_hubs
from osint_fusion.graph.fraud_rings import FraudRingAlert
from osint_fusion.graph.graph_builder import EntityGraphBuilder
from osint_fusion.ingest.sanitizer import sanitize_document
from osint_fusion.schemas import Entity, OSINTDocument

router = APIRouter(prefix="/api/v1")


class IngestResponse(BaseModel):
    doc_id: str
    status: str
    entities_count: int
    entities: list[Entity]
    duplicates_found: list[dict[str, Any]]


class DuplicateCluster(BaseModel):
    doc_id_a: str
    doc_id_b: str
    similarity: float


# Estado compartido en el proceso (in-memory con persistencia opcional)
_GRAPH_BUILDER = EntityGraphBuilder()
_LSH_INDEX = LSHIndex(num_perm=64, threshold=0.65, num_bands=16)


def get_graph() -> EntityGraphBuilder:
    return _GRAPH_BUILDER


def get_lsh() -> LSHIndex:
    return _LSH_INDEX


def reset_state() -> None:
    """Función de utilidad para tests y limpieza de estado."""
    _GRAPH_BUILDER.clear()
    _LSH_INDEX.buckets = [_LSH_INDEX.buckets[0].__class__(set) for _ in range(_LSH_INDEX.b)]
    _LSH_INDEX.signatures.clear()
    _LSH_INDEX.documents.clear()


@router.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "osint-fusion",
        "version": "0.1.0",
        "indexed_documents": _LSH_INDEX.size(),
        "graph_nodes": _GRAPH_BUILDER.graph.number_of_nodes(),
    }


@router.post(
    "/documents",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Ingest & Dedup"],
)
def ingest_document(doc: OSINTDocument):
    """Ingesta un documento de inteligencia, sanitiza PII, verifica duplicados LSH e indexa entidades en el grafo."""
    # 1. Sanitizar PII (tarjetas de crédito, emails personales, IPs internas)
    clean_doc = sanitize_document(doc)

    # 2. Verificar duplicados en LSH
    matches = _LSH_INDEX.query(clean_doc.content)
    duplicates_found = [{"doc_id": m[0], "similarity": m[1]} for m in matches if m[0] != clean_doc.id]

    # 3. Indexar documento en LSH
    _LSH_INDEX.insert(clean_doc.id, clean_doc.content)

    # 4. Extraer entidades e indexar en el grafo NetworkX
    extracted_entities = _GRAPH_BUILDER.ingest_text(clean_doc.content, doc_id=clean_doc.id)

    return IngestResponse(
        doc_id=clean_doc.id,
        status="ingested",
        entities_count=len(extracted_entities),
        entities=extracted_entities,
        duplicates_found=duplicates_found,
    )


@router.get(
    "/documents/duplicates",
    response_model=list[DuplicateCluster],
    tags=["Ingest & Dedup"],
)
def get_all_duplicates(threshold: float = Query(0.65, ge=0.1, le=1.0)):
    """Obtiene todos los pares de documentos duplicados o cuasi-duplicados detectados por MinHash LSH."""
    return _LSH_INDEX.find_all_duplicates(threshold=threshold)


@router.get("/entities", response_model=list[Entity], tags=["Graph & Entities"])
def list_entities(
    entity_type: Optional[str] = Query(None, alias="type", description="Filtrar por tipo (IP, DOMAIN, WALLET, etc.)"),
    limit: int = Query(100, ge=1, le=1000),
):
    """Lista las entidades presentes en el grafo de inteligencia."""
    results: list[Entity] = []
    for node, data in _GRAPH_BUILDER.graph.nodes(data=True):
        ntype = data.get("type", "UNKNOWN")
        if entity_type and ntype.upper() != entity_type.upper():
            continue
        results.append(
            Entity(
                id=str(node),
                type=ntype,
                value=data.get("value", str(node)),
                metadata={k: v for k, v in data.items() if k not in ("type", "value")},
            )
        )
        if len(results) >= limit:
            break
    return results


@router.get("/graph", tags=["Graph & Entities"])
def get_full_graph():
    """Devuelve la topología completa del grafo en formato Node-Link JSON (D3.js / Cytoscape)."""
    return _GRAPH_BUILDER.to_dict()


@router.get("/graph/{entity_id:path}/subgraph", tags=["Graph & Entities"])
def get_entity_subgraph(entity_id: str, radius: int = Query(1, ge=1, le=3)):
    """Devuelve el subgrafo inducido ego-network (k-hop) alrededor de una entidad clave."""
    if entity_id not in _GRAPH_BUILDER.graph:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entidad '{entity_id}' no encontrada en el grafo de inteligencia.",
        )
    sub = _GRAPH_BUILDER.get_subgraph(entity_id, radius=radius)
    return _GRAPH_BUILDER.to_dict(sub)


@router.get("/graph/export/gexf", tags=["Export"])
def export_gexf_stream():
    """Descarga el grafo en formato GEXF XML listo para su análisis en Gephi o Cytoscape."""
    xml_content = export_to_gexf(_GRAPH_BUILDER.graph)
    return Response(
        content=xml_content,
        media_type="application/xml",
        headers={"Content-Disposition": 'attachment; filename="osint_graph.gexf"'},
    )


@router.get("/analytics/metrics", tags=["Analytics"])
def get_graph_analytics():
    """Calcula y devuelve métricas topológicas de centralidad (degree, betweenness, pagerank)."""
    return _GRAPH_BUILDER.get_full_metrics()


@router.get("/analytics/top-hubs", tags=["Analytics"])
def get_top_hub_entities(
    metric: str = Query("pagerank", pattern="^(degree|betweenness|pagerank|closeness)$"),
    top_k: int = Query(10, ge=1, le=100),
):
    """Devuelve los principales hubs de inteligencia según la métrica topológica seleccionada."""
    return get_top_hubs(_GRAPH_BUILDER.graph, metric=metric, top_k=top_k)


@router.get("/analytics/fraud-rings", response_model=list[FraudRingAlert], tags=["Analytics"])
def get_fraud_rings():
    """Analiza la red en busca de anillos de fraude, ciclos de blanqueo y células colusivas."""
    return _GRAPH_BUILDER.detect_fraud_rings()

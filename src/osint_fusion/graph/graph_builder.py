"""Constructor y gestor del grafo de inteligencia de amenazas OSINT."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import networkx as nx

from osint_fusion.graph.centrality import calculate_centrality_metrics, get_top_hubs
from osint_fusion.graph.entity_extractor import EntityExtractor
from osint_fusion.graph.fraud_rings import FraudRingAlert, detect_fraud_rings
from osint_fusion.schemas import Entity, Relation


class EntityGraphBuilder:
    """Gestiona la topología de la red de entidades y relaciones OSINT."""

    def __init__(self):
        self.graph = nx.Graph()
        self.extractor = EntityExtractor()

    def add_entity(self, entity: Entity) -> None:
        """Añade un nodo entidad al grafo."""
        self.graph.add_node(
            entity.id,
            type=entity.type,
            value=entity.value,
            **entity.metadata,
        )

    def add_relation(self, relation: Relation) -> None:
        """Añade una arista de relación entre dos entidades."""
        self.graph.add_edge(
            relation.source_id,
            relation.target_id,
            relation=relation.relation_type,
            weight=relation.weight,
        )

    def ingest_text(
        self, text: str, doc_id: str = "", infer_relations: bool = True
    ) -> list[Entity]:
        """Extrae entidades e infiere relaciones desde texto no estructurado y las agrega al grafo.

        Args:
            text: Texto fuente.
            doc_id: ID del documento.
            infer_relations: Si es True, infiere aristas entre las entidades detectadas.

        Returns:
            Lista de entidades extraídas.
        """
        entities = self.extractor.extract_entities(text, doc_id=doc_id)
        for ent in entities:
            self.add_entity(ent)

        if infer_relations and len(entities) > 1:
            relations = self.extractor.infer_relations(entities, doc_id=doc_id)
            for rel in relations:
                self.add_relation(rel)

        return entities

    def get_centrality(self) -> dict[str, float]:
        """Calcula el grado de centralidad estándar de los nodos."""
        if len(self.graph) == 0:
            return {}
        return nx.degree_centrality(self.graph)

    def get_full_metrics(self) -> dict[str, Any]:
        """Devuelve un análisis topológico exhaustivo del grafo."""
        if len(self.graph) == 0:
            return {
                "nodes_count": 0,
                "edges_count": 0,
                "density": 0.0,
                "connected_components": 0,
                "centrality": {},
                "top_hubs": [],
            }

        return {
            "nodes_count": self.graph.number_of_nodes(),
            "edges_count": self.graph.number_of_edges(),
            "density": round(nx.density(self.graph), 4),
            "connected_components": nx.number_connected_components(self.graph),
            "centrality": calculate_centrality_metrics(self.graph),
            "top_hubs": get_top_hubs(self.graph, metric="pagerank", top_k=5),
        }

    def detect_fraud_rings(self) -> list[FraudRingAlert]:
        """Ejecuta detección de anillos de fraude y patrones de colusión."""
        return detect_fraud_rings(self.graph)

    def get_subgraph(self, entity_id: str, radius: int = 1) -> nx.Graph:
        """Extrae la red ego / subgrafo alrededor de una entidad específica.

        Args:
            entity_id: ID del nodo central.
            radius: Profundidad de saltos (k-hop).

        Returns:
            Subgrafo inducido de NetworkX.
        """
        if entity_id not in self.graph:
            return nx.Graph()
        nodes = nx.single_source_shortest_path_length(
            self.graph, entity_id, cutoff=radius
        ).keys()
        return self.graph.subgraph(nodes).copy()

    def to_dict(self, graph_obj: Optional[nx.Graph] = None) -> dict[str, Any]:
        """Exporta el grafo a formato Node-Link JSON compatible con D3.js y Cytoscape.js."""
        g = graph_obj if graph_obj is not None else self.graph
        data = nx.node_link_data(g)
        if "edges" in data and "links" not in data:
            data["links"] = data["edges"]
        return data

    def clear(self) -> None:
        """Reinicia el grafo."""
        self.graph.clear()

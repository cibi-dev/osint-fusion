import networkx as nx
from typing import Dict, List
from osint_fusion.schemas import Entity, Relation

class EntityGraphBuilder:
    def __init__(self):
        self.graph = nx.Graph()

    def add_entity(self, entity: Entity) -> None:
        self.graph.add_node(entity.id, type=entity.type, value=entity.value, **entity.metadata)

    def add_relation(self, relation: Relation) -> None:
        self.graph.add_edge(relation.source_id, relation.target_id, relation=relation.relation_type, weight=relation.weight)

    def get_centrality(self) -> Dict[str, float]:
        if len(self.graph) == 0:
            return {}
        return nx.degree_centrality(self.graph)

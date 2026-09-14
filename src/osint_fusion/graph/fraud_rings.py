"""Módulo de detección de anillos de fraude, células botnet y redes de blanqueo o colusión."""

from __future__ import annotations

from typing import Any, Dict, List, Set
import networkx as nx
from pydantic import BaseModel, Field


class FraudRingAlert(BaseModel):
    """Alerta estructurada de anillo de fraude o infraestructura maliciosa coordinada."""

    ring_id: str
    pattern_type: str  # CYCLE, CLIQUE, STAR_HUB, DENSE_CLUSTER
    severity: str  # CRITICAL, HIGH, MEDIUM
    risk_score: float = Field(ge=0.0, le=1.0)
    nodes: list[str]
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)


def detect_fraud_rings(graph: nx.Graph) -> list[FraudRingAlert]:
    """Detecta patrones anómalos y topologías de colusión en el grafo de inteligencia:

    1. Ciclos cerrados (Cycle Basis) de longitud 3 a 6 (ej. triangulación de pagos / proxies circulares).
    2. Cliques maximales densos de tamaño >= 3 (células de agentes o identidades sintéticas altamente interconectadas).
    3. Concentradores en estrella (Star Hubs): Nodos (como wallets o dominios de C2) conectados a una cantidad desproporcionada de actores.

    Args:
        graph: Grafo NetworkX de entidades y relaciones.

    Returns:
        Lista de alertas ordenadas por nivel de severidad y riesgo.
    """
    alerts: list[FraudRingAlert] = []
    if len(graph) < 3:
        return alerts

    # 1. Detección de Ciclos Cerrados (Cycle basis)
    cycle_counter = 1
    cycles = nx.cycle_basis(graph)
    for cycle in cycles:
        if 3 <= len(cycle) <= 6:
            # Calcular severidad basada en tipos de nodos (si involucra wallets o actors)
            types = {graph.nodes[n].get("type", "") for n in cycle}
            is_critical = "WALLET" in types or "ACTOR" in types

            risk = 0.85 if is_critical else 0.65
            sev = "CRITICAL" if is_critical else "HIGH"

            alerts.append(
                FraudRingAlert(
                    ring_id=f"ring-cycle-{cycle_counter:03d}",
                    pattern_type="CYCLE",
                    severity=sev,
                    risk_score=risk,
                    nodes=cycle,
                    description=f"Detección de ciclo cerrado de {len(cycle)} nodos con posible triangulación o encubrimiento.",
                    metadata={"node_types": list(types), "cycle_length": len(cycle)},
                )
            )
            cycle_counter += 1

    # 2. Detección de Cliques (Subgrafos completamente conectados >= 3)
    clique_counter = 1
    cliques = list(nx.find_cliques(graph))
    for clique in cliques:
        if len(clique) >= 3:
            types = {graph.nodes[n].get("type", "") for n in clique}
            alerts.append(
                FraudRingAlert(
                    ring_id=f"ring-clique-{clique_counter:03d}",
                    pattern_type="CLIQUE",
                    severity="HIGH",
                    risk_score=min(0.95, 0.70 + (len(clique) * 0.05)),
                    nodes=clique,
                    description=f"Célula clique altamente colusiva de {len(clique)} identidades completamente conectadas.",
                    metadata={"clique_size": len(clique), "node_types": list(types)},
                )
            )
            clique_counter += 1

    # 3. Concentradores en Estrella (Star Hubs) con alto grado
    hub_counter = 1
    degree_dict = dict(graph.degree())
    avg_degree = sum(degree_dict.values()) / max(1, len(degree_dict))

    for node, deg in degree_dict.items():
        # Nodo con grado al menos 3 y más del triple de la media
        if deg >= 4 and deg > (avg_degree * 2.0):
            node_type = graph.nodes[node].get("type", "")
            node_val = graph.nodes[node].get("value", node)
            neighbors = list(graph.neighbors(node))

            alerts.append(
                FraudRingAlert(
                    ring_id=f"hub-star-{hub_counter:03d}",
                    pattern_type="STAR_HUB",
                    severity="HIGH" if node_type in ("WALLET", "IP", "DOMAIN") else "MEDIUM",
                    risk_score=0.75,
                    nodes=[node] + neighbors,
                    description=f"Nodo concentrador estrella '{node_val}' ({node_type}) vinculado a {deg} entidades periféricas.",
                    metadata={"hub_node": node, "hub_type": node_type, "degree": deg},
                )
            )
            hub_counter += 1

    # Ordenar por risk_score descendente
    alerts.sort(key=lambda a: a.risk_score, reverse=True)
    return alerts

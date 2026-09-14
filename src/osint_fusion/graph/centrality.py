"""Cálculo y análisis de métricas de centralidad topológica en grafos OSINT."""

from __future__ import annotations

from typing import Any, Dict
import networkx as nx


def calculate_centrality_metrics(graph: nx.Graph) -> dict[str, dict[str, float]]:
    """Calcula métricas de centralidad para todos los nodos del grafo.

    Incluye:
    - Degree Centrality: Importancia por volumen directo de conexiones.
    - Betweenness Centrality: Nodos puente / cuellos de botella de información.
    - PageRank: Influencia ponderada por prestigio de los vecinos.
    - Closeness Centrality: Proximidad media a todos los demás nodos.

    Args:
        graph: Grafo de NetworkX.

    Returns:
        Diccionario con las métricas calculadas indexadas por tipo de métrica.
    """
    if len(graph) == 0:
        return {
            "degree": {},
            "betweenness": {},
            "pagerank": {},
            "closeness": {},
        }

    degree = nx.degree_centrality(graph)

    # Betweenness centrality (aproximada si el grafo es muy grande)
    k = min(len(graph), 200) if len(graph) > 200 else None
    betweenness = nx.betweenness_centrality(graph, k=k, weight="weight")

    # PageRank con amortiguamiento estándar 0.85
    try:
        pagerank = nx.pagerank(graph, alpha=0.85, weight="weight", max_iter=100)
    except Exception:
        # Fallback a uniforme si no converge
        pagerank = {node: 1.0 / len(graph) for node in graph.nodes()}

    # Closeness centrality
    closeness = nx.closeness_centrality(graph)

    return {
        "degree": {node: round(val, 5) for node, val in degree.items()},
        "betweenness": {node: round(val, 5) for node, val in betweenness.items()},
        "pagerank": {node: round(val, 5) for node, val in pagerank.items()},
        "closeness": {node: round(val, 5) for node, val in closeness.items()},
    }


def get_top_hubs(
    graph: nx.Graph, metric: str = "pagerank", top_k: int = 10
) -> list[dict[str, Any]]:
    """Devuelve las entidades más críticas del grafo según la métrica indicada.

    Args:
        graph: Grafo NetworkX.
        metric: degree | betweenness | pagerank | closeness.
        top_k: Número máximo de entidades a devolver.

    Returns:
        Lista ordenada de diccionarios con node_id, tipo, valor y puntuación.
    """
    metrics = calculate_centrality_metrics(graph)
    scores = metrics.get(metric, metrics["degree"])

    sorted_nodes = sorted(scores.items(), key=lambda item: item[1], reverse=True)[:top_k]

    hubs = []
    for node_id, score in sorted_nodes:
        attrs = graph.nodes.get(node_id, {})
        hubs.append(
            {
                "node_id": node_id,
                "type": attrs.get("type", "UNKNOWN"),
                "value": attrs.get("value", node_id),
                "score": score,
                "metric": metric,
            }
        )
    return hubs

"""Exportador de grafos de inteligencia OSINT a formato GEXF y JSON compatible con Gephi y Cytoscape."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional
import networkx as nx


def _clean_graph_for_gexf(graph: nx.Graph) -> nx.Graph:
    """Crea una copia del grafo transformando atributos complejos en cadenas para compatibilidad GEXF XML."""
    g_clean = nx.Graph()
    for node, attrs in graph.nodes(data=True):
        clean_attrs = {}
        for k, v in attrs.items():
            if isinstance(v, (str, int, float, bool)):
                clean_attrs[k] = v
            elif v is None:
                clean_attrs[k] = ""
            else:
                clean_attrs[k] = str(v)
        g_clean.add_node(str(node), **clean_attrs)

    for u, v, attrs in graph.edges(data=True):
        clean_attrs = {}
        for k, val in attrs.items():
            if isinstance(val, (str, int, float, bool)):
                clean_attrs[k] = val
            elif val is None:
                clean_attrs[k] = ""
            else:
                clean_attrs[k] = str(val)
        g_clean.add_edge(str(u), str(v), **clean_attrs)

    return g_clean


def export_to_gexf(graph: nx.Graph, filepath: Optional[str | Path] = None) -> str:
    """Exporta el grafo NetworkX a formato estándar GEXF (Graph Exchange XML Format).

    Args:
        graph: Grafo NetworkX de entidades y relaciones.
        filepath: Ruta opcional en disco para guardar el archivo .gexf.

    Returns:
        Cadena XML con la especificación GEXF.
    """
    g_clean = _clean_graph_for_gexf(graph)
    gexf_lines = list(nx.generate_gexf(g_clean, encoding="utf-8"))
    xml_content = "\n".join(gexf_lines)

    if filepath:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(xml_content, encoding="utf-8")

    return xml_content


def export_to_json(graph: nx.Graph, filepath: Optional[str | Path] = None) -> str:
    """Exporta el grafo NetworkX a JSON en formato Node-Link (D3.js / Cytoscape).

    Args:
        graph: Grafo de NetworkX.
        filepath: Ruta opcional en disco para guardar el archivo .json.

    Returns:
        Cadena JSON formateada.
    """
    data = nx.node_link_data(graph)
    if "edges" in data and "links" not in data:
        data["links"] = data["edges"]
    json_str = json.dumps(data, indent=2, ensure_ascii=False)

    if filepath:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json_str, encoding="utf-8")

    return json_str

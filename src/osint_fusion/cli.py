"""CLI interactiva y de automatización para OSINT Fusion Engine."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from osint_fusion.api.routes import get_graph, get_lsh
from osint_fusion.exporters.gexf import export_to_gexf, export_to_json
from osint_fusion.graph.centrality import get_top_hubs
from osint_fusion.ingest.sanitizer import sanitize_document
from osint_fusion.schemas import OSINTDocument


def cmd_ingest(args: argparse.Namespace) -> int:
    """Ingesta texto o archivo, extrae entidades y detecta duplicados con LSH."""
    content = ""
    if args.file:
        p = Path(args.file)
        if not p.exists():
            print(f"[ERROR] Archivo no encontrado: {args.file}", file=sys.stderr)
            return 1
        content = p.read_text(encoding="utf-8")
    elif args.text:
        content = args.text
    else:
        print("[ERROR] Debe especificar --text o --file", file=sys.stderr)
        return 1

    doc = OSINTDocument(
        id=args.id or f"cli-doc-{hash(content) & 0xFFFFFFFF:08x}",
        source=args.source or "cli",
        title=args.title or "CLI Input",
        content=content,
        timestamp="2026-09-14T00:00:00Z",
    )

    clean_doc = sanitize_document(doc)
    lsh = get_lsh()
    graph = get_graph()

    # Chequear duplicados
    matches = lsh.query(clean_doc.content)
    lsh.insert(clean_doc.id, clean_doc.content)
    entities = graph.ingest_text(clean_doc.content, doc_id=clean_doc.id)

    print(f"=== Documento Ingestado: {clean_doc.id} ===")
    print(f"Entidades detectadas: {len(entities)}")
    for e in entities:
        print(f"  [{e.type}] {e.value} (ID: {e.id})")

    dups = [m for m in matches if m[0] != clean_doc.id]
    if dups:
        print("\n[ALERTA DE DUPLICADOS ENCONTRADOS]:")
        for doc_id, sim in dups:
            print(f"  - Documento {doc_id} (Similitud Jaccard: {sim * 100:.1f}%)")
    else:
        print("\nNo se detectaron duplicados previos en el índice LSH.")

    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    """Muestra métricas topológicas de centralidad del grafo."""
    graph = get_graph()
    metrics = graph.get_full_metrics()

    print("=== Métricas Topológicas del Grafo OSINT ===")
    print(f"Total Nodos: {metrics['nodes_count']}")
    print(f"Total Aristas: {metrics['edges_count']}")
    print(f"Densidad de Red: {metrics['density']}")
    print(f"Componentes Conectados: {metrics['connected_components']}")

    top = get_top_hubs(graph.graph, metric=args.metric, top_k=args.top_k)
    print(f"\nTop-{args.top_k} Nodos Críticos por Centralidad ({args.metric.upper()}):")
    for i, h in enumerate(top, 1):
        print(f"  {i}. [{h['type']}] {h['value']} — Score: {h['score']:.5f}")

    return 0


def cmd_detect_rings(args: argparse.Namespace) -> int:
    """Detecta anillos de fraude, células colusivas y concentradores sospechosos."""
    graph = get_graph()
    alerts = graph.detect_fraud_rings()

    print(f"=== Análisis de Anillos de Fraude y Células Colusivas ({len(alerts)} alertas) ===")
    if not alerts:
        print("No se encontraron patrones de colusión o ciclos sospechosos.")
        return 0

    for a in alerts:
        print(f"\n[{a.severity}] {a.ring_id} — Patrón: {a.pattern_type} (Riesgo: {a.risk_score:.2f})")
        print(f"  Descripción: {a.description}")
        print(f"  Nodos involucrados ({len(a.nodes)}): {', '.join(a.nodes[:6])}")

    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Exporta el grafo a formato GEXF o JSON."""
    graph = get_graph().graph
    output_path = Path(args.output)
    fmt = args.format.lower()

    if fmt == "gexf":
        export_to_gexf(graph, filepath=output_path)
        print(f"Grafo exportado exitosamente a GEXF (Gephi): {output_path}")
    elif fmt == "json":
        export_to_json(graph, filepath=output_path)
        print(f"Grafo exportado exitosamente a Node-Link JSON: {output_path}")
    else:
        print(f"[ERROR] Formato no soportado: {fmt}. Use 'gexf' o 'json'", file=sys.stderr)
        return 1

    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Inicia el servidor API FastAPI con Uvicorn."""
    import uvicorn
    print(f"Iniciando OSINT Fusion API en {args.host}:{args.port}...")
    uvicorn.run("osint_fusion.api.app:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def main(argv: list[str] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="osint-fusion",
        description="OSINT Fusion Engine — MinHash LSH, Análisis de Grafos de Amenazas y Detección de Fraude",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando ingest
    p_ingest = subparsers.add_parser("ingest", help="Ingestar texto o archivo y extraer entidades")
    p_ingest.add_argument("--text", "-t", type=str, help="Texto sin procesar para análisis")
    p_ingest.add_argument("--file", "-f", type=str, help="Ruta al archivo con el texto")
    p_ingest.add_argument("--id", type=str, help="ID personalizado del documento")
    p_ingest.add_argument("--source", type=str, default="cli", help="Origen del reporte")
    p_ingest.add_argument("--title", type=str, default="Reporte OSINT", help="Título del reporte")
    p_ingest.set_defaults(func=cmd_ingest)

    # Subcomando graph-metrics
    p_metrics = subparsers.add_parser("graph-metrics", help="Calcular centralidad y top hubs")
    p_metrics.add_argument("--metric", choices=["pagerank", "degree", "betweenness", "closeness"], default="pagerank")
    p_metrics.add_argument("--top-k", type=int, default=5, help="Cantidad de hubs a mostrar")
    p_metrics.set_defaults(func=cmd_metrics)

    # Subcomando detect-rings
    p_rings = subparsers.add_parser("detect-rings", help="Detectar ciclos sospechosos y anillos de fraude")
    p_rings.set_defaults(func=cmd_detect_rings)

    # Subcomando export
    p_export = subparsers.add_parser("export", help="Exportar grafo a GEXF o JSON")
    p_export.add_argument("--format", choices=["gexf", "json"], default="gexf", help="Formato de exportación")
    p_export.add_argument("--output", "-o", required=True, help="Ruta de destino del archivo")
    p_export.set_defaults(func=cmd_export)

    # Subcomando serve
    p_serve = subparsers.add_parser("serve", help="Levantar servidor web FastAPI")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host de enlace")
    p_serve.add_argument("--port", type=int, default=8000, help="Puerto TCP")
    p_serve.add_argument("--reload", action="store_true", help="Activar auto-recarga de desarrollo")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

# OSINT-Fusion Engine (`cibi-dev/osint-fusion`)

Digital intelligence correlation and entity relationship graph builder with MinHash/LSH deduplication.

## Highlights
- **Sublinear Fuzzy Deduplication:** 64-bit MinHash signatures with Jaccard similarity estimation.
- **Relational Entity Graphs:** NetworkX-backed analysis of suspects, domains, IPs, and crypto addresses.
- **Zero Cloud Cost:** 100% local in-memory/SQLite execution with REST API and GEXF export.

## Quickstart
```bash
pip install -e ".[dev]"
osint-fusion --help
pytest -v
```

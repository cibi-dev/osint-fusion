# OSINT Fusion Engine 🌐🔍

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com)
[![NetworkX](https://img.shields.io/badge/NetworkX-3.2%2B-blue.svg)](https://networkx.org)
[![Security: Bandit](https://img.shields.io/badge/Security-Bandit%20Passing-brightgreen.svg)](https://github.com/PyCQA/bandit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero-Cost](https://img.shields.io/badge/API%20Cost-%240.00%2Fmo-success.svg)](https://github.com/cibi-dev/osint-fusion)

> **Motor de inteligencia de fuentes abiertas (OSINT), deduplicación probabilística MinHash/LSH, análisis topológico de grafos de amenazas (NetworkX) y detección de anillos de fraude / colusión.**

Diseñado bajo la filosofía **Zero-Cost Sovereign Defense**: ejecución 100% local en CPU Linux, sin suscripciones a APIs privativas, con protección estricta contra SSRF (CWE-918), parseo seguro anti-XXE (`defusedxml`) y sanitización automática de PII.

---

## 🏗️ Arquitectura del Sistema

```
                            FUENTES EXTERNAS OSINT
                 [ Feeds RSS/Atom ]   [ Certificate Transparency ]
                          │                       │
                          ▼                       ▼
            ┌──────────────────────────────────────────────┐
            │   Capa de Ingesta Segura (Anti-SSRF / XXE)    │
            │   - Resolución DNS anti-RFC1918 & metadata   │
            │   - Parser DefusedXML anti Billion Laughs    │
            │   - Sanitizador PII (Tarjetas, IPs, Emails)  │
            └──────────────────────┬───────────────────────┘
                                   │
                                   ▼
            ┌──────────────────────────────────────────────┐
            │    Motor MinHash + LSH (Deduplicación O(1))  │
            │   - Shingler de k-palabras y k-caracteres    │
            │   - b=16 bandas x r=4 filas (64 funciones)   │
            │   - Búsqueda sublineal de candidatos cuasi-  │
            │     duplicados y almacenamiento SQLite local │
            └──────────────────────┬───────────────────────┘
                                   │
                                   ▼
            ┌──────────────────────────────────────────────┐
            │   Extractor de IoCs y Grafos de Inteligencia │
            │   - Regex validadas: IPs, Dominios, Wallets, │
            │     Emails, Hashes (MD5/SHA256), CVEs, APTs  │
            │   - Inferencia semántica de relaciones       │
            └──────────────────────┬───────────────────────┘
                                   │
                                   ▼
            ┌──────────────────────────────────────────────┐
            │        Análisis Topológico & Detección       │
            │   - Centralidad: Degree, Betweenness, PR     │
            │   - Detección de Anillos de Fraude (Ciclos)  │
            │   - Detección de Cliques y Star Hubs         │
            └──────────────────────┬───────────────────────┘
                                   │
                  ┌────────────────┴────────────────┐
                  ▼                                 ▼
        [ FastAPI REST API ]             [ Exportadores GEXF / JSON ]
   (Docs OpenAPI / Swagger UI)            (Gephi, Cytoscape, D3.js)
```

---

## ⚡ Características Principales

1. **Ingesta Fortalecida (Hardened Ingestion):**
   - **Anti-SSRF Estricto (CWE-918):** Validación de resolución de IPs contra RFC 1918, loopback `127.0.0.0/8`, link-local `169.254.0.0/16` y endpoints de metadata cloud (`169.254.169.254`).
   - **Anti-XXE (CWE-611):** Parseo seguro con `defusedxml` que neutraliza ataques *Billion Laughs* y *Quadratic Blowup*.
   - **Sanitización de Privacidad PII:** Enmascaramiento automático de tarjetas de crédito (PAN), correos personales e IPs de infraestructura interna.

2. **Deduplicación Sublineal MinHash / LSH:**
   - Tokenización por $k$-shingles de palabras y caracteres.
   - Particionamiento en $b$ bandas y $r$ filas con hashing $MD5$ parametrizado (`usedforsecurity=False` auditado por Bandit B324).
   - Detección instantánea de reportes cuasi-duplicados y campañas coordinadas.
   - Persistencia local en SQLite para escalabilidad sin infraestructura externa.

3. **Grafo de Amenazas y Detección de Fraude:**
   - Extracción de IoCs: IPs públicas enrutables, dominios FQDN, wallets Ethereum / Bitcoin, hashes SHA-256/MD5, identificadores CVE y grupos APT.
   - **Métricas de Centralidad:** Degree Centrality, Betweenness Centrality, PageRank y Closeness Centrality.
   - **Patrones de Colusión:**
     - **Ciclos Cerrados:** Detección de triangulación o encubrimiento financiero en $3 \le N \le 6$ nodos.
     - **Cliques Maximales:** Identificación de células altamente conectadas ($K \ge 3$).
     - **Star Hubs:** Detección de concentradores anómalos de infraestructura o blanqueo.

4. **API REST FastAPI & Exportación:**
   - Endpoints asíncronos para ingesta, consulta de ego-subgrafos ($k$-hop), métricas y alertas.
   - Exportación nativa a **GEXF XML** (para visualización e investigación forense en **Gephi**) y **Node-Link JSON** (para D3.js/Cytoscape).

---

## 🚀 Instalación y Uso Rápido

### 1. Clonar e Instalar

```bash
git clone https://github.com/cibi-dev/osint-fusion.git
cd osint-fusion

# Instalar dependencias en entorno local
pip install -e .
```

### 2. Uso mediante CLI (`osint-fusion`)

```bash
# Ingestar texto y extraer entidades IoCs con detección de duplicados
osint-fusion ingest --text "APT29 coordinated attacks using 185.220.101.5 and domain c2-payload.top. BTC wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa."

# Calcular métricas topológicas de centralidad
osint-fusion graph-metrics --metric pagerank --top-k 5

# Detectar anillos de fraude y ciclos sospechosos
osint-fusion detect-rings

# Exportar grafo para Gephi
osint-fusion export --format gexf -o ./osint_graph.gexf
```

### 3. Levantar la API REST FastAPI

```bash
osint-fusion serve --host 127.0.0.1 --port 8000
# Documentación interactiva disponible en: http://127.0.0.1:8000/docs
```

---

## 🧪 Pruebas y Seguridad (DevSecOps)

El proyecto cumple con los 17 estándares canónicos de DevSecOps del workspace:

```bash
# Ejecutar suite completa de pruebas unitarias e integración (48 tests, cobertura >= 90%)
pytest -v --cov=src/osint_fusion

# Análisis estático de seguridad (SAST) sin alertas
bandit -r src/ -ll

# Detección de secretos o credenciales
gitleaks detect -v
```

---

## 📄 Licencia

Distribuido bajo la Licencia MIT. Consulta `LICENSE` para más información.

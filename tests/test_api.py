import pytest
from starlette.testclient import TestClient

from osint_fusion.api.app import app
from osint_fusion.api.routes import reset_state


@pytest.fixture(autouse=True)
def clean_state():
    reset_state()
    yield
    reset_state()


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client: TestClient):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "osint-fusion"


def test_ingest_document_and_duplicate_detection(client: TestClient):
    payload1 = {
        "id": "doc-01",
        "source": "threat-intel",
        "title": "Campaign Alpha",
        "content": "APT28 using domain c2-server.evil.ru and IP 185.220.101.5 for exfiltration.",
        "timestamp": "2026-09-14T10:00:00Z",
    }
    res1 = client.post("/api/v1/documents", json=payload1)
    assert res1.status_code == 201
    data1 = res1.json()
    assert data1["status"] == "ingested"
    assert data1["entities_count"] >= 2
    assert len(data1["duplicates_found"]) == 0

    # Ingestar documento casi idéntico
    payload2 = {
        "id": "doc-02",
        "source": "threat-intel",
        "title": "Campaign Alpha Variation",
        "content": "APT28 using domain c2-server.evil.ru and IP 185.220.101.5 for exfiltration purposes.",
        "timestamp": "2026-09-14T11:00:00Z",
    }
    res2 = client.post("/api/v1/documents", json=payload2)
    assert res2.status_code == 201
    data2 = res2.json()
    assert len(data2["duplicates_found"]) >= 1
    assert data2["duplicates_found"][0]["doc_id"] == "doc-01"


def test_list_entities_and_filter(client: TestClient):
    payload = {
        "id": "doc-03",
        "source": "osint",
        "title": "Crypto Laundering",
        "content": "Attacker laundered funds via Ethereum 0x71C7656EC7ab88b098defB751B7401B5f6d8976F and domain ransom.top.",
        "timestamp": "2026-09-14T12:00:00Z",
    }
    client.post("/api/v1/documents", json=payload)

    # Listar todas
    res_all = client.get("/api/v1/entities")
    assert res_all.status_code == 200
    entities = res_all.json()
    assert len(entities) >= 2

    # Filtrar por WALLET
    res_wallet = client.get("/api/v1/entities?type=WALLET")
    assert res_wallet.status_code == 200
    wallet_ents = res_wallet.json()
    assert len(wallet_ents) == 1
    assert wallet_ents[0]["type"] == "WALLET"


def test_get_graph_and_subgraph(client: TestClient):
    payload = {
        "id": "doc-04",
        "source": "cert",
        "title": "Cert Transparency",
        "content": "Domain malicious-bank.com with email admin@malicious-bank.com.",
        "timestamp": "2026-09-14T12:00:00Z",
    }
    client.post("/api/v1/documents", json=payload)

    res_graph = client.get("/api/v1/graph")
    assert res_graph.status_code == 200
    graph_data = res_graph.json()
    assert "nodes" in graph_data

    # Subgrafo de entidad existente
    res_sub = client.get("/api/v1/graph/domain:malicious-bank.com/subgraph?radius=1")
    assert res_sub.status_code == 200
    sub_data = res_sub.json()
    assert "nodes" in sub_data

    # Subgrafo de entidad inexistente -> 404
    res_404 = client.get("/api/v1/graph/nonexistent:999/subgraph")
    assert res_404.status_code == 404


def test_export_gexf_endpoint(client: TestClient):
    payload = {
        "id": "doc-05",
        "source": "osint",
        "title": "Network Hub",
        "content": "APT29 communicating with 185.220.101.5.",
        "timestamp": "2026-09-14T12:00:00Z",
    }
    client.post("/api/v1/documents", json=payload)

    res_export = client.get("/api/v1/graph/export/gexf")
    assert res_export.status_code == 200
    assert "application/xml" in res_export.headers.get("content-type", "")
    assert b"<gexf" in res_export.content


def test_analytics_endpoints(client: TestClient):
    payload = {
        "id": "doc-06",
        "source": "osint",
        "title": "Graph Hub",
        "content": "APT29 used 185.220.101.5 and c2.top.",
        "timestamp": "2026-09-14T12:00:00Z",
    }
    client.post("/api/v1/documents", json=payload)

    res_metrics = client.get("/api/v1/analytics/metrics")
    assert res_metrics.status_code == 200
    data = res_metrics.json()
    assert data["nodes_count"] >= 2
    assert "centrality" in data

    res_hubs = client.get("/api/v1/analytics/top-hubs?metric=pagerank&top_k=3")
    assert res_hubs.status_code == 200
    assert isinstance(res_hubs.json(), list)

    res_rings = client.get("/api/v1/analytics/fraud-rings")
    assert res_rings.status_code == 200
    assert isinstance(res_rings.json(), list)


def test_api_duplicates_list_endpoint(client: TestClient):
    payload_a = {
        "id": "dup-a",
        "source": "osint",
        "title": "Dup Test A",
        "content": "Malware payload communicates with domain malicious-c2-node.org and IP 185.220.101.5.",
        "timestamp": "2026-09-14T12:00:00Z",
    }
    payload_b = {
        "id": "dup-b",
        "source": "osint",
        "title": "Dup Test B",
        "content": "Malware payload communicates with domain malicious-c2-node.org and IP 185.220.101.5 exactly.",
        "timestamp": "2026-09-14T12:05:00Z",
    }
    client.post("/api/v1/documents", json=payload_a)
    client.post("/api/v1/documents", json=payload_b)

    res = client.get("/api/v1/documents/duplicates?threshold=0.5")
    assert res.status_code == 200
    dups = res.json()
    assert len(dups) >= 1
    assert dups[0]["similarity"] >= 0.5


def test_api_invalid_subgraph_radius_validation(client: TestClient):
    # radius > 3 should fail validation 422
    res = client.get("/api/v1/graph/some-entity/subgraph?radius=10")
    assert res.status_code == 422


def test_api_filter_nonexistent_entity_type(client: TestClient):
    res = client.get("/api/v1/entities?type=NONEXISTENT_TYPE")
    assert res.status_code == 200
    assert res.json() == []

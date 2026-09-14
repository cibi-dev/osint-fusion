import pytest
import networkx as nx
from osint_fusion.graph import (
    EntityGraphBuilder,
    EntityExtractor,
    calculate_centrality_metrics,
    get_top_hubs,
    detect_fraud_rings,
)
from osint_fusion.schemas import Entity, Relation


def test_entity_extractor_finds_iocs():
    extractor = EntityExtractor()
    sample_text = (
        "APT29 threat actor targeted victims using command and control at c2-server.malicious.top "
        "and IP 185.220.101.5. Ransom payment requested to BTC wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
        "and ETH address 0x71C7656EC7ab88b098defB751B7401B5f6d8976F. "
        "Associated email: hacker@darknet-group.org. Related vulnerability: CVE-2023-38606. "
        "SHA-256 payload hash: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae."
    )
    entities = extractor.extract_entities(sample_text, doc_id="report-01")
    types = {e.type for e in entities}
    
    assert "ACTOR" in types
    assert "DOMAIN" in types
    assert "IP" in types
    assert "WALLET" in types
    assert "EMAIL" in types
    assert "CVE" in types
    assert "HASH_SHA256" in types
    
    # Inferencia de relaciones
    relations = extractor.infer_relations(entities, doc_id="report-01")
    assert len(relations) > 0
    rel_types = {r.relation_type for r in relations}
    assert "USES_INFRASTRUCTURE" in rel_types or "CO_OCCURRENCE" in rel_types


def test_entity_extractor_ignores_private_ips():
    extractor = EntityExtractor()
    text = "Internal node 192.168.1.10 contacted 10.0.0.5 and loopback 127.0.0.1."
    entities = extractor.extract_entities(text)
    ip_entities = [e for e in entities if e.type == "IP"]
    assert len(ip_entities) == 0


def test_centrality_metrics():
    g = nx.path_graph(5)  # 0 - 1 - 2 - 3 - 4
    metrics = calculate_centrality_metrics(g)
    
    assert "degree" in metrics
    assert "betweenness" in metrics
    assert "pagerank" in metrics
    assert "closeness" in metrics
    
    # El nodo 2 es el centro del path graph
    assert metrics["betweenness"][2] > metrics["betweenness"][0]


def test_top_hubs():
    g = nx.star_graph(5)  # Central node 0 connected to 1,2,3,4,5
    nx.set_node_attributes(g, "WALLET", "type")
    nx.set_node_attributes(g, "wallet-0", "value")
    
    hubs = get_top_hubs(g, metric="degree", top_k=1)
    assert len(hubs) == 1
    assert hubs[0]["node_id"] == 0


def test_fraud_rings_cycle_detection():
    builder = EntityGraphBuilder()
    # Construir un ciclo cerrado de 3 nodos (walletA -> walletB -> walletC -> walletA)
    e1 = Entity(id="wallet:0xaaa", type="WALLET", value="0xaaa")
    e2 = Entity(id="wallet:0xbbb", type="WALLET", value="0xbbb")
    e3 = Entity(id="wallet:0xccc", type="WALLET", value="0xccc")
    
    builder.add_entity(e1)
    builder.add_entity(e2)
    builder.add_entity(e3)
    
    builder.add_relation(Relation(source_id=e1.id, target_id=e2.id, relation_type="TRANSFER"))
    builder.add_relation(Relation(source_id=e2.id, target_id=e3.id, relation_type="TRANSFER"))
    builder.add_relation(Relation(source_id=e3.id, target_id=e1.id, relation_type="TRANSFER"))
    
    alerts = builder.detect_fraud_rings()
    assert len(alerts) >= 1
    cycle_alerts = [a for a in alerts if a.pattern_type == "CYCLE"]
    assert len(cycle_alerts) >= 1
    assert cycle_alerts[0].severity == "CRITICAL"
    assert cycle_alerts[0].risk_score >= 0.8


def test_fraud_rings_clique_detection():
    builder = EntityGraphBuilder()
    # Crear un clique K4
    for i in range(4):
        builder.add_entity(Entity(id=f"user:{i}", type="PERSON", value=f"person_{i}"))
    
    for i in range(4):
        for j in range(i + 1, 4):
            builder.add_relation(Relation(source_id=f"user:{i}", target_id=f"user:{j}", relation_type="COLLUDES"))
            
    alerts = builder.detect_fraud_rings()
    clique_alerts = [a for a in alerts if a.pattern_type == "CLIQUE"]
    assert len(clique_alerts) >= 1
    assert len(clique_alerts[0].nodes) == 4


def test_graph_builder_ingest_text_and_subgraph():
    builder = EntityGraphBuilder()
    text = "APT29 deployed backdoor from malicious domain bad-actor.xyz using 198.51.100.88."
    entities = builder.ingest_text(text, doc_id="doc-99")
    
    assert len(entities) >= 2
    metrics = builder.get_full_metrics()
    assert metrics["nodes_count"] >= 2
    assert metrics["edges_count"] >= 1
    
    first_node = entities[0].id
    sub = builder.get_subgraph(first_node, radius=1)
    assert first_node in sub.nodes
    
    node_link = builder.to_dict()
    assert "nodes" in node_link
    assert "links" in node_link


def test_empty_graph_metrics():
    builder = EntityGraphBuilder()
    metrics = builder.get_full_metrics()
    assert metrics["nodes_count"] == 0
    assert metrics["edges_count"] == 0
    assert builder.get_centrality() == {}
    assert builder.detect_fraud_rings() == []
    assert len(builder.get_subgraph("non_existent").nodes) == 0


def test_fraud_rings_star_hub_detection():
    builder = EntityGraphBuilder()
    # Crear un concentrador malicioso central conectado a 6 periferias
    hub = Entity(id="wallet:0x_super_launderer", type="WALLET", value="0x_super_launderer")
    builder.add_entity(hub)
    for i in range(6):
        bot = Entity(id=f"actor:bot_{i}", type="ACTOR", value=f"bot_{i}")
        builder.add_entity(bot)
        builder.add_relation(Relation(source_id=bot.id, target_id=hub.id, relation_type="FUNDS"))

    alerts = builder.detect_fraud_rings()
    star_alerts = [a for a in alerts if a.pattern_type == "STAR_HUB"]
    assert len(star_alerts) >= 1
    assert hub.id in star_alerts[0].nodes


def test_disconnected_graph_metrics():
    builder = EntityGraphBuilder()
    # Dos islas desconectadas: (A-B) y (C-D)
    builder.add_entity(Entity(id="a", type="IP", value="1.1.1.1"))
    builder.add_entity(Entity(id="b", type="IP", value="2.2.2.2"))
    builder.add_entity(Entity(id="c", type="IP", value="3.3.3.3"))
    builder.add_entity(Entity(id="d", type="IP", value="4.4.4.4"))
    builder.add_relation(Relation(source_id="a", target_id="b", relation_type="LINK"))
    builder.add_relation(Relation(source_id="c", target_id="d", relation_type="LINK"))

    metrics = builder.get_full_metrics()
    assert metrics["connected_components"] == 2
    assert metrics["density"] < 1.0


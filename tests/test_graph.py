from osint_fusion.schemas import Entity, Relation

def test_graph_construction(graph_builder):
    e1 = Entity(id="ent-1", type="PERSON", value="John Doe")
    e2 = Entity(id="ent-2", type="DOMAIN", value="darkweb-node.example")
    graph_builder.add_entity(e1)
    graph_builder.add_entity(e2)
    graph_builder.add_relation(Relation(source_id="ent-1", target_id="ent-2", relation_type="OWNS"))
    centrality = graph_builder.get_centrality()
    assert "ent-1" in centrality
    assert centrality["ent-1"] == 1.0

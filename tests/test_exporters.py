import json
import xml.etree.ElementTree as ET
from pathlib import Path
import networkx as nx

from osint_fusion.exporters.gexf import export_to_gexf, export_to_json


def test_export_to_gexf(tmp_path: Path):
    g = nx.Graph()
    g.add_node("actor:apt29", type="ACTOR", value="APT29", count=5)
    g.add_node("domain:bad.org", type="DOMAIN", value="bad.org")
    g.add_edge("actor:apt29", "domain:bad.org", relation="USES", weight=1.5)

    gexf_file = tmp_path / "test.gexf"
    xml_str = export_to_gexf(g, filepath=gexf_file)

    assert "<gexf" in xml_str
    assert "actor:apt29" in xml_str
    assert "domain:bad.org" in xml_str
    assert gexf_file.exists()

    # Validar que es XML válido
    root = ET.fromstring(xml_str)
    assert "gexf" in root.tag.lower()


def test_export_to_json(tmp_path: Path):
    g = nx.Graph()
    g.add_node("node-1", type="IP", value="1.1.1.1")
    g.add_node("node-2", type="DOMAIN", value="example.com")
    g.add_edge("node-1", "node-2", weight=1.0)

    json_file = tmp_path / "test.json"
    json_str = export_to_json(g, filepath=json_file)

    data = json.loads(json_str)
    assert "nodes" in data
    assert "links" in data or "edges" in data
    assert len(data["nodes"]) == 2
    assert json_file.exists()

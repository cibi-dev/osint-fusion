import pytest
from pathlib import Path
from osint_fusion.cli import main
from osint_fusion.api.routes import reset_state


@pytest.fixture(autouse=True)
def clean_state():
    reset_state()
    yield
    reset_state()


def test_cli_ingest_text(capsys):
    ret = main([
        "ingest",
        "--text",
        "APT29 coordinated attacks using 185.220.101.5 and domain c2-payload.top",
        "--id",
        "test-doc-01",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Documento Ingestado: test-doc-01" in captured.out
    assert "Entidades detectadas:" in captured.out
    assert "ACTOR" in captured.out


def test_cli_ingest_file(tmp_path: Path, capsys):
    doc_file = tmp_path / "threat_report.txt"
    doc_file.write_text("Lazarus group deployed malware linking to btc wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.", encoding="utf-8")

    ret = main([
        "ingest",
        "--file",
        str(doc_file),
        "--id",
        "file-doc-02",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    assert "file-doc-02" in captured.out
    assert "WALLET" in captured.out


def test_cli_metrics_and_rings(capsys):
    # Ingestar algo primero
    main([
        "ingest",
        "--text",
        "APT28 used 185.220.101.5 and domain malicious-server.com",
    ])
    capsys.readouterr()  # limpiar buffer

    ret_m = main(["graph-metrics", "--metric", "degree", "--top-k", "3"])
    assert ret_m == 0
    captured_m = capsys.readouterr()
    assert "Métricas Topológicas del Grafo OSINT" in captured_m.out

    ret_r = main(["detect-rings"])
    assert ret_r == 0
    captured_r = capsys.readouterr()
    assert "Análisis de Anillos de Fraude" in captured_r.out


def test_cli_export(tmp_path: Path, capsys):
    main([
        "ingest",
        "--text",
        "APT29 beaconing to 185.220.101.5",
    ])
    capsys.readouterr()

    out_gexf = tmp_path / "export.gexf"
    ret = main(["export", "--format", "gexf", "-o", str(out_gexf)])
    assert ret == 0
    assert out_gexf.exists()

    out_json = tmp_path / "export.json"
    ret_json = main(["export", "--format", "json", "-o", str(out_json)])
    assert ret_json == 0
    assert out_json.exists()


def test_cli_missing_args():
    with pytest.raises(SystemExit):
        main([])

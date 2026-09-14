import pytest
from pathlib import Path
from osint_fusion.dedup import LSHIndex, MinHasher, k_shingles_word, k_shingles_char, normalize_text


def test_normalize_and_shingler():
    text = "Threat Actor APT29 identified using cobalt strike beacon."
    clean = normalize_text(text)
    assert "apt29" in clean
    
    word_shingles = k_shingles_word(text, k=2)
    assert len(word_shingles) > 0
    assert "threat actor" in word_shingles
    
    char_shingles = k_shingles_char(text, k=4)
    assert len(char_shingles) > 0


def test_shingler_edge_cases():
    assert k_shingles_word("", k=3) == set()
    assert k_shingles_char("", k=5) == set()
    
    short = "hello"
    assert k_shingles_word(short, k=3) == {"hello"}


def test_lsh_exact_and_near_duplicates():
    lsh = LSHIndex(num_perm=64, threshold=0.6, num_bands=16)
    
    doc1 = "The phishing campaign targets financial institutions using spoofed banking domains and malicious macros."
    doc2 = "The phishing campaign targets financial institutions using spoofed banking domains and malicious attachments."
    doc3 = "Quantum computing research achieves breakthrough in topological qubits and cryogenic processors."
    
    lsh.insert("doc-1", doc1)
    lsh.insert("doc-2", doc2)
    lsh.insert("doc-3", doc3)
    
    assert lsh.size() == 3
    
    # Consulta con doc1
    matches = lsh.query(doc1, threshold=0.5)
    matched_ids = [m[0] for m in matches]
    assert "doc-1" in matched_ids
    assert "doc-2" in matched_ids
    assert "doc-3" not in matched_ids
    
    # Consulta con doc3
    matches_doc3 = lsh.query(doc3, threshold=0.8)
    assert len(matches_doc3) == 1
    assert matches_doc3[0][0] == "doc-3"


def test_lsh_find_all_duplicates():
    lsh = LSHIndex(num_perm=64, threshold=0.6, num_bands=16)
    
    docA = "Critical vulnerability in OpenSSL library allows remote memory disclosure heartbleed style."
    docB = "Critical vulnerability in OpenSSL library allows remote memory disclosure heartbleed flaw."
    docC = "Unrelated weather forecast predicting heavy rainfall in coastal regions."
    
    lsh.insert("sec-A", docA)
    lsh.insert("sec-B", docB)
    lsh.insert("weather-C", docC)
    
    dups = lsh.find_all_duplicates(threshold=0.6)
    assert len(dups) >= 1
    pair = dups[0]
    ids = {pair["doc_id_a"], pair["doc_id_b"]}
    assert ids == {"sec-A", "sec-B"}
    assert pair["similarity"] >= 0.6


def test_lsh_invalid_params():
    with pytest.raises(ValueError):
        # 16 bands * 5 rows = 80 > 64 num_perm
        LSHIndex(num_perm=64, num_bands=16, rows_per_band=5)

    lsh = LSHIndex(num_perm=64, num_bands=16, rows_per_band=4)
    with pytest.raises(ValueError):
        lsh.insert_signature("bad-sig", [1, 2, 3])


def test_lsh_sqlite_persistence(tmp_path: Path):
    db_file = tmp_path / "test_lsh.db"
    lsh = LSHIndex(num_perm=64, threshold=0.7, num_bands=16, db_path=db_file)
    
    text = "Cyber espionage campaign attributed to Lazarus Group targeting cryptocurrency exchanges."
    lsh.insert("lazarus-1", text)
    
    assert db_file.exists()
    
    # Comprobar que reabrir o consultar encuentra el documento
    matches = lsh.query(text)
    assert len(matches) >= 1
    assert matches[0][0] == "lazarus-1"
    assert matches[0][1] >= 0.95

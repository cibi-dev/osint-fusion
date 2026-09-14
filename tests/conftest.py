import sys
from pathlib import Path
import pytest

src_path = str(Path(__file__).resolve().parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from osint_fusion.dedup.minhash import MinHasher
from osint_fusion.graph.graph_builder import EntityGraphBuilder

@pytest.fixture
def hasher():
    return MinHasher(num_perm=64)

@pytest.fixture
def graph_builder():
    return EntityGraphBuilder()

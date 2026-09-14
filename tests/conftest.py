import pytest
from osint_fusion.dedup.minhash import MinHasher
from osint_fusion.graph.graph_builder import EntityGraphBuilder

@pytest.fixture
def hasher():
    return MinHasher(num_perm=64)

@pytest.fixture
def graph_builder():
    return EntityGraphBuilder()

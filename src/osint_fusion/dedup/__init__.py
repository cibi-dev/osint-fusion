"""Submódulo de deduplicación probabilística MinHash y LSH."""

from osint_fusion.dedup.lsh_index import LSHIndex
from osint_fusion.dedup.minhash import MinHasher
from osint_fusion.dedup.shingler import k_shingles_char, k_shingles_word, normalize_text

__all__ = [
    "MinHasher",
    "LSHIndex",
    "normalize_text",
    "k_shingles_word",
    "k_shingles_char",
]

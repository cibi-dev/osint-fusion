import hashlib
from typing import List, Set

class MinHasher:
    def __init__(self, num_perm: int = 64):
        self.num_perm = num_perm

    def shingle(self, text: str, k: int = 3) -> Set[str]:
        clean = "".join(ch.lower() for ch in text if ch.isalnum() or ch.isspace())
        tokens = clean.split()
        if len(tokens) < k:
            return {clean}
        return {" ".join(tokens[i:i+k]) for i in range(len(tokens) - k + 1)}

    def compute_signature(self, shingles: Set[str]) -> List[int]:
        sig = []
        for i in range(self.num_perm):
            min_val = float("inf")
            for sh in shingles:
                val = int(hashlib.md5(f"{i}:{sh}".encode("utf-8"), usedforsecurity=False).hexdigest()[:8], 16)
                if val < min_val:
                    min_val = val
            sig.append(int(min_val))
        return sig

    @staticmethod
    def estimate_jaccard(sig1: List[int], sig2: List[int]) -> float:
        if not sig1 or not sig2 or len(sig1) != len(sig2):
            return 0.0
        matches = sum(1 for a, b in zip(sig1, sig2) if a == b)
        return matches / len(sig1)

"""Índice LSH (Locality-Sensitive Hashing) para deduplicación sublineal de documentos OSINT."""

from __future__ import annotations

import hashlib
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from osint_fusion.dedup.minhash import MinHasher
from osint_fusion.dedup.shingler import k_shingles_word


class LSHIndex:
    """Índice Locality-Sensitive Hashing basado en bandas y filas para MinHash.

    Permite indexar documentos de inteligencia y buscar candidatos duplicados o
    cuasi-duplicados en tiempo sublineal O(1) por cubeta.
    """

    def __init__(
        self,
        num_perm: int = 64,
        threshold: float = 0.7,
        num_bands: int = 16,
        rows_per_band: Optional[int] = None,
        db_path: Optional[str | Path] = None,
    ):
        """Inicializa el índice LSH.

        Args:
            num_perm: Número total de funciones hash en la signatura MinHash (debe ser divisible por num_bands).
            threshold: Umbral estimado de similitud de Jaccard mínima para considerar duplicado.
            num_bands: Número de bandas (b).
            rows_per_band: Número de filas por banda (r). Si es None, se calcula como num_perm // num_bands.
            db_path: Ruta opcional a base de datos SQLite para persistencia en disco.
        """
        self.num_perm = num_perm
        self.threshold = threshold
        self.b = num_bands
        self.r = rows_per_band if rows_per_band is not None else (num_perm // num_bands)
        if self.b * self.r > self.num_perm:
            raise ValueError(
                f"num_bands * rows_per_band ({self.b * self.r}) no puede superar num_perm ({self.num_perm})"
            )

        self.hasher = MinHasher(num_perm=self.num_perm)
        # Tablas hash en memoria: band_idx -> bucket_hash -> set(doc_id)
        self.buckets: list[dict[str, set[str]]] = [defaultdict(set) for _ in range(self.b)]
        # Almacén de signaturas en memoria: doc_id -> list[int]
        self.signatures: dict[str, list[int]] = {}
        # Textos originales indexados: doc_id -> text
        self.documents: dict[str, str] = {}

        self.db_path = Path(db_path) if db_path else None
        if self.db_path:
            self._init_sqlite()

    def _init_sqlite(self) -> None:
        """Inicializa esquema SQLite para persistencia local de LSH."""
        if not self.db_path:
            return
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS lsh_documents (
                        doc_id TEXT PRIMARY KEY,
                        signature TEXT NOT NULL,
                        text_content TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS lsh_buckets (
                        band_idx INTEGER NOT NULL,
                        bucket_key TEXT NOT NULL,
                        doc_id TEXT NOT NULL,
                        PRIMARY KEY (band_idx, bucket_key, doc_id)
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_band_key ON lsh_buckets (band_idx, bucket_key)")
        finally:
            conn.close()

    def _hash_band(self, band_idx: int, band_slice: list[int]) -> str:
        """Calcula el hash MD5 seguro de una banda de signaturas."""
        raw = f"{band_idx}:" + ",".join(str(val) for val in band_slice)
        return hashlib.md5(raw.encode("utf-8"), usedforsecurity=False).hexdigest()

    def insert(self, doc_id: str, text: str, k_shingle: int = 3) -> list[int]:
        """Indexa un documento extrayendo shingles y calculando su signatura MinHash.

        Args:
            doc_id: Identificador único del documento.
            text: Contenido textual a procesar.
            k_shingle: Tamaño k de palabras para shingling.

        Returns:
            Signatura MinHash calculada.
        """
        shingles = k_shingles_word(text, k=k_shingle)
        sig = self.hasher.compute_signature(shingles)
        self.insert_signature(doc_id, sig, text=text)
        return sig

    def insert_signature(self, doc_id: str, signature: list[int], text: Optional[str] = None) -> None:
        """Indexa directamente una signatura MinHash en las cubetas correspondientes.

        Args:
            doc_id: Identificador único.
            signature: Vector de enteros de longitud num_perm.
            text: Texto opcional asociado al documento.
        """
        if len(signature) < self.b * self.r:
            raise ValueError(
                f"Longitud de signatura ({len(signature)}) insuficiente para b={self.b}, r={self.r}"
            )

        self.signatures[doc_id] = signature
        if text is not None:
            self.documents[doc_id] = text

        sqlite_records = []
        for band_idx in range(self.b):
            start = band_idx * self.r
            end = start + self.r
            band_slice = signature[start:end]
            bucket_key = self._hash_band(band_idx, band_slice)
            self.buckets[band_idx][bucket_key].add(doc_id)
            if self.db_path:
                sqlite_records.append((band_idx, bucket_key, doc_id))

        if self.db_path:
            conn = sqlite3.connect(self.db_path)
            try:
                with conn:
                    sig_str = ",".join(str(x) for x in signature)
                    conn.execute(
                        "INSERT OR REPLACE INTO lsh_documents (doc_id, signature, text_content) VALUES (?, ?, ?)",
                        (doc_id, sig_str, text),
                    )
                    conn.executemany(
                        "INSERT OR IGNORE INTO lsh_buckets (band_idx, bucket_key, doc_id) VALUES (?, ?, ?)",
                        sqlite_records,
                    )
            finally:
                conn.close()

    def query(self, text: str, threshold: Optional[float] = None, k_shingle: int = 3) -> list[tuple[str, float]]:
        """Busca documentos similares en el índice para un texto dado.

        Args:
            text: Texto a consultar.
            threshold: Umbral Jaccard específico (por defecto usa self.threshold).
            k_shingle: Tamaño k para shingling.

        Returns:
            Lista de tuplas (doc_id, estimated_jaccard_similarity) ordenada de mayor a menor similitud.
        """
        shingles = k_shingles_word(text, k=k_shingle)
        query_sig = self.hasher.compute_signature(shingles)
        return self.query_signature(query_sig, threshold=threshold)

    def query_signature(self, signature: list[int], threshold: Optional[float] = None) -> list[tuple[str, float]]:
        """Consulta el índice LSH a partir de una signatura MinHash.

        Args:
            signature: Signatura MinHash del elemento buscado.
            threshold: Umbral Jaccard mínimo.

        Returns:
            Lista de tuplas (doc_id, similitud) que superan el umbral.
        """
        target_thresh = threshold if threshold is not None else self.threshold
        candidates: set[str] = set()

        for band_idx in range(self.b):
            start = band_idx * self.r
            end = start + self.r
            band_slice = signature[start:end]
            bucket_key = self._hash_band(band_idx, band_slice)
            bucket_docs = self.buckets[band_idx].get(bucket_key)
            if bucket_docs:
                candidates.update(bucket_docs)

        results: list[tuple[str, float]] = []
        for cand_id in candidates:
            cand_sig = self.signatures.get(cand_id)
            if cand_sig is None:
                continue
            sim = MinHasher.estimate_jaccard(signature, cand_sig)
            if sim >= target_thresh:
                results.append((cand_id, round(sim, 4)))

        results.sort(key=lambda item: item[1], reverse=True)
        return results

    def find_all_duplicates(self, threshold: Optional[float] = None) -> list[dict[str, Any]]:
        """Detecta todos los pares y clusters de cuasi-duplicados existentes en el índice.

        Args:
            threshold: Umbral Jaccard mínimo.

        Returns:
            Lista de diccionarios con doc1, doc2, similarity.
        """
        target_thresh = threshold if threshold is not None else self.threshold
        seen_pairs: set[tuple[str, str]] = set()
        duplicates: list[dict[str, Any]] = []

        # Buscar candidatos comparando solo elementos que compartan al menos una cubeta
        for band_dict in self.buckets:
            for bucket_key, doc_set in band_dict.items():
                if len(doc_set) < 2:
                    continue
                docs = sorted(list(doc_set))
                for i in range(len(docs)):
                    for j in range(i + 1, len(docs)):
                        pair = (docs[i], docs[j])
                        if pair in seen_pairs:
                            continue
                        seen_pairs.add(pair)
                        sig1 = self.signatures[docs[i]]
                        sig2 = self.signatures[docs[j]]
                        sim = MinHasher.estimate_jaccard(sig1, sig2)
                        if sim >= target_thresh:
                            duplicates.append(
                                {
                                    "doc_id_a": docs[i],
                                    "doc_id_b": docs[j],
                                    "similarity": round(sim, 4),
                                }
                            )

        duplicates.sort(key=lambda d: d["similarity"], reverse=True)
        return duplicates

    def size(self) -> int:
        """Devuelve el total de documentos indexados."""
        return len(self.signatures)

"""Módulo de tokenización y shingling de texto para deduplicación MinHash."""

from __future__ import annotations

import re


def normalize_text(text: str) -> str:
    """Limpia el texto eliminando signos de puntuación no informativos y normalizando espacios."""
    cleaned = re.sub(r"[^\w\s]", " ", text.lower())
    return " ".join(cleaned.split())


def k_shingles_word(text: str, k: int = 3) -> set[str]:
    """Genera un conjunto de shingles de k palabras consecutivas (n-gramas de palabras).

    Args:
        text: Texto de entrada.
        k: Longitud del shingle en palabras.

    Returns:
        Conjunto de shingles únicos.
    """
    clean = normalize_text(text)
    words = clean.split()
    if not words:
        return set()
    if len(words) < k:
        return {" ".join(words)}
    return {" ".join(words[i : i + k]) for i in range(len(words) - k + 1)}


def k_shingles_char(text: str, k: int = 5) -> set[str]:
    """Genera un conjunto de n-gramas de caracteres sobre el texto normalizado.

    Args:
        text: Texto de entrada.
        k: Longitud del shingle en caracteres.

    Returns:
        Conjunto de shingles de caracteres únicos.
    """
    clean = "".join(ch.lower() for ch in text if ch.isalnum() or ch.isspace())
    clean = " ".join(clean.split())
    if len(clean) < k:
        return {clean} if clean else set()
    return {clean[i : i + k] for i in range(len(clean) - k + 1)}

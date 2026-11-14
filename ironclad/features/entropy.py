"""
IRONCLAD Cryptographic & Information-Theoretic Entropy Engine.

Computes Shannon entropy, block-level entropy distributions, and Chi-Square
goodness-of-fit to distinguish structured plaintext from compressed or encrypted data.
"""

from __future__ import annotations

import math
from typing import Dict, List, Tuple


def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy $H(X) = - \\sum_{i=0}^{255} p_i \\log_2(p_i)$ for byte data.

    Returns:
        Float value in range [0.0, 8.0]. Plaintext English is typically 3.5 - 5.0.
        Encrypted or compressed ciphertext is typically 7.2 - 8.0.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return float(round(entropy, 4))


def block_entropy(data: bytes, block_size: int = 64) -> List[float]:
    """
    Compute sliding window / block-based entropy along the byte payload.
    Reveals transitions between unencrypted headers and encrypted body segments.

    Args:
        data: Raw payload bytes.
        block_size: Size of each evaluation block.

    Returns:
        List of Shannon entropy values per block.
    """
    if not data or block_size <= 0:
        return []

    entropies = []
    for i in range(0, len(data), block_size):
        chunk = data[i : i + block_size]
        entropies.append(shannon_entropy(chunk))

    return entropies


def chi_squared_uniformity(data: bytes) -> float:
    """
    Compute Chi-Squared test statistic against an ideal uniform distribution.
    For $N$ bytes across 256 possible byte values, expected count $E_i = N / 256$.
    $\\chi^2 = \\sum_{i=0}^{255} \\frac{(O_i - E_i)^2}{E_i}$.

    Lower values (around 256) denote uniform randomness (AES/TLS/ChaCha20),
    whereas large values indicate strong non-random structure (HTTP, JSON, code).
    """
    if len(data) < 256:
        return 0.0

    n = len(data)
    expected = n / 256.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    chi_sq = sum(((observed - expected) ** 2) / expected for observed in counts)
    return float(round(chi_sq, 4))


def analyze_payload_cryptography(data: bytes) -> Tuple[float, float, bool]:
    """
    Analyze payload bytes for indicators of encryption or high-density compression.

    Returns:
        Tuple of (shannon_entropy, chi_squared, is_likely_encrypted)
    """
    if not data:
        return 0.0, 0.0, False

    entropy = shannon_entropy(data)
    chi = chi_squared_uniformity(data)
    # Typical threshold for encrypted/compressed payload: Shannon > 7.2
    is_encrypted = entropy >= 7.2
    return entropy, chi, is_encrypted

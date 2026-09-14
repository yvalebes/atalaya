"""Shannon-style entropy estimates for both character passwords and passphrases.

For a string drawn uniformly from a pool of size N, each symbol carries
log2(N) bits of information, so an L-symbol string carries L * log2(N) bits.
This is the same estimate used by tools like zxcvbn's "brute-force" baseline;
it assumes the generation process (ours, via `secrets`) is actually uniform,
which is a fair assumption here since we control the pool.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class EntropyRating:
    bits: float
    label: str


_THRESHOLDS = (
    (28, "muy debil"),
    (36, "debil"),
    (60, "aceptable"),
    (80, "fuerte"),
    (100, "muy fuerte"),
)


def rate(bits: float) -> str:
    for threshold, label in _THRESHOLDS:
        if bits < threshold:
            return label
    return "excelente"


def bits_from_pool(pool_size: int, length: int) -> EntropyRating:
    if pool_size <= 1 or length <= 0:
        return EntropyRating(0.0, rate(0.0))
    bits = length * math.log2(pool_size)
    return EntropyRating(bits, rate(bits))


def bits_from_wordlist(wordlist_size: int, word_count: int) -> EntropyRating:
    return bits_from_pool(wordlist_size, word_count)

"""Diceware-style passphrases drawn from the EFF large wordlist.

Real dice give each of the list's 7776 words (6^5) equal odds; we reproduce
that with secrets.choice() over the same list instead of rolling physical
dice, so the odds stay uniform and the source stays a CSPRNG.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from importlib import resources

_SEPARATOR_DEFAULT = "-"


@lru_cache(maxsize=1)
def load_wordlist() -> tuple[str, ...]:
    raw = resources.files("forgekey.data").joinpath("eff_large_wordlist.txt").read_text(
        encoding="utf-8"
    )
    words = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # Each line is "<5-digit dice roll>\t<word>"; we only need the word.
        parts = line.split()
        words.append(parts[-1])
    return tuple(words)


def generate_passphrase(word_count: int = 6, separator: str = _SEPARATOR_DEFAULT) -> str:
    if word_count < 1:
        raise ValueError("word_count debe ser al menos 1")
    words = load_wordlist()
    chosen = [secrets.choice(words) for _ in range(word_count)]
    return separator.join(chosen)


def wordlist_size() -> int:
    return len(load_wordlist())

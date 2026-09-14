"""Random password generation backed exclusively by the `secrets` module.

`random` is a Mersenne Twister: given enough output it is fully predictable,
which makes it unsafe for anything that guards an account. `secrets` draws
from the operating system's CSPRNG (os.urandom), so past output gives an
attacker no leverage over future draws.

The output length and block format are fixed on purpose, not configurable:
16 random characters, grouped into 4 blocks of 4 and joined with "-"
(19 characters on screen). There is no parameter anywhere in this module
that accepts a different length — that's deliberate, so no caller (CLI
flag, GUI control, or future code) can weaken the generated password by
asking for a shorter one.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from . import charsets

PASSWORD_LENGTH = 16
BLOCK_SIZE = 4
BLOCK_SEPARATOR = "-"


@dataclass
class GeneratorOptions:
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False

    def active_pools(self) -> list[str]:
        pools = []
        if self.use_lowercase:
            pools.append(charsets.LOWERCASE)
        if self.use_uppercase:
            pools.append(charsets.UPPERCASE)
        if self.use_digits:
            pools.append(charsets.DIGITS)
        if self.use_symbols:
            pools.append(charsets.SYMBOLS)

        if self.exclude_ambiguous:
            pools = [charsets.strip_ambiguous(p) for p in pools]
        return [p for p in pools if p]


class NoCharacterPoolSelected(ValueError):
    pass


def generate_password(options: GeneratorOptions) -> str:
    """Returns the final, block-formatted password — e.g. "aB3!-kP9x-Qz2m-7Ht$".

    There is no way to get the unformatted 16-character string from the
    public API: every consumer (GUI, CLI, HIBP check, history) sees and
    handles the exact same string the user will actually use as their
    password, hyphens included.
    """
    raw = _generate_raw(options)
    return _format_in_blocks(raw)


def _generate_raw(options: GeneratorOptions) -> str:
    pools = options.active_pools()
    if not pools:
        raise NoCharacterPoolSelected("selecciona al menos una categoria de caracteres")

    # One guaranteed character per active category so the fixed length
    # can't accidentally skip a whole class the user asked for.
    chosen = [secrets.choice(pool) for pool in pools]

    full_pool = "".join(pools)
    remaining = PASSWORD_LENGTH - len(chosen)
    chosen.extend(secrets.choice(full_pool) for _ in range(remaining))

    _shuffle_in_place(chosen)
    return "".join(chosen)


def _format_in_blocks(raw: str) -> str:
    blocks = [raw[i : i + BLOCK_SIZE] for i in range(0, len(raw), BLOCK_SIZE)]
    return BLOCK_SEPARATOR.join(blocks)


def _shuffle_in_place(items: list) -> None:
    """Fisher-Yates shuffle using secrets.randbelow so every permutation of
    positions is equally likely — the mandatory characters end up nowhere
    more predictable than the filler ones."""
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]

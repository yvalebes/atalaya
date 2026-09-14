"""Character pools used by the generator, plus the ambiguous-glyph exclusion set."""

LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"

# No hyphen here on purpose: the generator's output is block-formatted with
# "-" as a structural separator, so a randomly drawn "-" would be visually
# indistinguishable from one of those separators.
SYMBOLS = "!\"#$%&'()*+,./:;<=>?@[\\]^_`{|}~"

# Glyphs that are easy to confuse with each other in most fonts and in
# handwriting: zero/O, one/lowercase-L/uppercase-I, and the pipe that reads
# like an L or a 1 in monospace terminals.
AMBIGUOUS = "0O1lI|"


def strip_ambiguous(pool: str) -> str:
    return "".join(ch for ch in pool if ch not in AMBIGUOUS)

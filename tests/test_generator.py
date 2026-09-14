import pytest

from forgekey.core import charsets
from forgekey.core.generator import (
    BLOCK_SEPARATOR,
    BLOCK_SIZE,
    PASSWORD_LENGTH,
    GeneratorOptions,
    NoCharacterPoolSelected,
    generate_password,
)


def _raw(password: str) -> str:
    return password.replace(BLOCK_SEPARATOR, "")


def test_output_has_fixed_block_format():
    password = generate_password(GeneratorOptions())
    blocks = password.split(BLOCK_SEPARATOR)
    assert len(blocks) == PASSWORD_LENGTH // BLOCK_SIZE
    assert all(len(block) == BLOCK_SIZE for block in blocks)
    assert len(password) == PASSWORD_LENGTH + (len(blocks) - 1)


def test_raw_character_count_is_always_sixteen():
    password = generate_password(GeneratorOptions())
    assert len(_raw(password)) == PASSWORD_LENGTH


def test_separator_never_appears_as_a_random_character():
    # The only "-" characters allowed in the output are the 3 structural
    # separators — none of the character pools may contain one, or a random
    # draw could be mistaken for a block boundary.
    assert BLOCK_SEPARATOR not in charsets.LOWERCASE
    assert BLOCK_SEPARATOR not in charsets.UPPERCASE
    assert BLOCK_SEPARATOR not in charsets.DIGITS
    assert BLOCK_SEPARATOR not in charsets.SYMBOLS


def test_no_pools_selected_raises():
    options = GeneratorOptions(
        use_lowercase=False, use_uppercase=False, use_digits=False, use_symbols=False
    )
    with pytest.raises(NoCharacterPoolSelected):
        generate_password(options)


def test_contains_at_least_one_of_each_selected_category():
    password = generate_password(GeneratorOptions())
    raw = _raw(password)
    assert any(c in charsets.LOWERCASE for c in raw)
    assert any(c in charsets.UPPERCASE for c in raw)
    assert any(c in charsets.DIGITS for c in raw)
    assert any(c in charsets.SYMBOLS for c in raw)


def test_respects_disabled_categories():
    options = GeneratorOptions(use_uppercase=False, use_digits=False, use_symbols=False)
    password = generate_password(options)
    assert all(c in charsets.LOWERCASE for c in _raw(password))


def test_exclude_ambiguous_removes_confusable_chars():
    options = GeneratorOptions(exclude_ambiguous=True)
    for _ in range(50):
        password = generate_password(options)
        assert not any(c in charsets.AMBIGUOUS for c in _raw(password))


def test_output_only_uses_selected_pools():
    options = GeneratorOptions(
        use_uppercase=True, use_lowercase=False, use_digits=True, use_symbols=False
    )
    allowed = set(charsets.UPPERCASE + charsets.DIGITS)
    for _ in range(50):
        password = generate_password(options)
        assert set(_raw(password)) <= allowed


def test_distribution_is_not_degenerate_across_many_generations():
    # Any single 16-character password won't hit every pool member, but
    # across many generations each active category should show up — this
    # would fail if the fill step silently favored one pool.
    options = GeneratorOptions()
    seen_lower = seen_upper = seen_digit = seen_symbol = False
    for _ in range(200):
        raw = _raw(generate_password(options))
        seen_lower |= any(c in charsets.LOWERCASE for c in raw)
        seen_upper |= any(c in charsets.UPPERCASE for c in raw)
        seen_digit |= any(c in charsets.DIGITS for c in raw)
        seen_symbol |= any(c in charsets.SYMBOLS for c in raw)
    assert seen_lower and seen_upper and seen_digit and seen_symbol


def test_repeated_generations_are_not_identical():
    passwords = {generate_password(GeneratorOptions()) for _ in range(20)}
    assert len(passwords) == 20

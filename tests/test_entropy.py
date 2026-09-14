import math

from forgekey.core.entropy import bits_from_pool, bits_from_wordlist, rate


def test_bits_from_pool_matches_formula():
    result = bits_from_pool(pool_size=26, length=10)
    assert math.isclose(result.bits, 10 * math.log2(26), rel_tol=1e-9)


def test_zero_length_gives_zero_bits():
    result = bits_from_pool(pool_size=95, length=0)
    assert result.bits == 0.0


def test_bits_from_wordlist_matches_pool_formula():
    result = bits_from_wordlist(wordlist_size=7776, word_count=6)
    assert math.isclose(result.bits, 6 * math.log2(7776), rel_tol=1e-9)


def test_rating_thresholds_are_monotonic():
    weak = rate(20)
    strong = rate(90)
    assert weak != strong


def test_more_bits_never_produces_a_weaker_label():
    order = ["muy debil", "debil", "aceptable", "fuerte", "muy fuerte", "excelente"]
    previous_index = -1
    for bits in range(0, 140, 5):
        label = rate(bits)
        index = order.index(label)
        assert index >= previous_index
        previous_index = index

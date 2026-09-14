from atalaya.core.passphrase import generate_passphrase, load_wordlist, wordlist_size


def test_wordlist_loads_expected_size():
    assert wordlist_size() == 7776


def test_wordlist_entries_are_lowercase_and_unique():
    words = load_wordlist()
    assert len(words) == len(set(words))
    assert all(word == word.lower() for word in words)


def test_passphrase_has_requested_word_count():
    phrase = generate_passphrase(word_count=8)
    assert len(phrase.split("-")) == 8


def test_passphrase_uses_only_wordlist_entries():
    words = set(load_wordlist())
    phrase = generate_passphrase(word_count=6)
    assert all(word in words for word in phrase.split("-"))


def test_custom_separator():
    phrase = generate_passphrase(word_count=4, separator=" ")
    assert len(phrase.split(" ")) == 4

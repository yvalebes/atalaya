import pytest

from forgekey.core.vault import Vault, VaultNotInitialized, WrongMasterPassword


def _vault(tmp_path):
    return Vault(tmp_path / "vault.json")


def test_add_and_reveal_roundtrip(tmp_path):
    vault = _vault(tmp_path)
    vault.add_entry(
        "correct horse battery staple",
        site="github.com",
        username="alice",
        password="s3cr3t!",
        bits=80.0,
        label="fuerte",
        mode="password",
    )

    entries = vault.list_entries()
    assert len(entries) == 1
    assert entries[0].site == "github.com"
    assert entries[0].username == "alice"
    assert entries[0].encrypted_password != "s3cr3t!"

    revealed = vault.reveal(entries[0].id, "correct horse battery staple")
    assert revealed == "s3cr3t!"


def test_password_never_stored_in_plaintext(tmp_path):
    vault = _vault(tmp_path)
    vault.add_entry(
        "master",
        site="a.com",
        username="",
        password="unmistakable-secret-value",
        bits=1,
        label="l",
        mode="password",
    )
    raw_contents = (tmp_path / "vault.json").read_text(encoding="utf-8")
    assert "unmistakable-secret-value" not in raw_contents


def test_wrong_master_password_on_reveal_raises(tmp_path):
    vault = _vault(tmp_path)
    vault.add_entry("correct horse", site="a.com", username="", password="x", bits=1, label="l", mode="password")
    entry = vault.list_entries()[0]
    with pytest.raises(WrongMasterPassword):
        vault.reveal(entry.id, "wrong password")


def test_wrong_master_password_on_second_add_is_rejected(tmp_path):
    vault = _vault(tmp_path)
    vault.add_entry("correct horse", site="a.com", username="", password="x", bits=1, label="l", mode="password")
    with pytest.raises(WrongMasterPassword):
        vault.add_entry(
            "a different password",
            site="b.com",
            username="",
            password="y",
            bits=1,
            label="l",
            mode="password",
        )
    # the rejected attempt must not have been persisted
    assert len(vault.list_entries()) == 1


def test_reveal_before_any_entry_raises(tmp_path):
    vault = _vault(tmp_path)
    with pytest.raises(VaultNotInitialized):
        vault.reveal("whatever", "pw")


def test_reveal_unknown_id_raises_key_error(tmp_path):
    vault = _vault(tmp_path)
    vault.add_entry("pw", site="a.com", username="", password="x", bits=1, label="l", mode="password")
    with pytest.raises(KeyError):
        vault.reveal("not-a-real-id", "pw")


def test_delete_removes_entry(tmp_path):
    vault = _vault(tmp_path)
    vault.add_entry("pw", site="a.com", username="", password="x", bits=1, label="l", mode="password")
    entry_id = vault.list_entries()[0].id
    vault.delete(entry_id)
    assert vault.list_entries() == []


def test_list_entries_does_not_require_master_password(tmp_path):
    vault = _vault(tmp_path)
    vault.add_entry("pw", site="netflix.com", username="bob", password="x", bits=1, label="l", mode="password")
    # no master password argument at all — metadata should still be readable
    entries = vault.list_entries()
    assert entries[0].site == "netflix.com"
    assert entries[0].username == "bob"

"""Local, encrypted history of generated passwords.

Site and username are stored in the clear — they aren't secrets on their
own and browsing history shouldn't require unlocking anything. The password
itself is only ever persisted as a Fernet token. The encryption key is
derived from a master password via PBKDF2-HMAC-SHA256 (480,000 iterations,
OWASP's 2023 baseline for PBKDF2-SHA256) with a random per-vault salt. The
master password itself is never written to disk — only the salt needed to
re-derive its key, plus a small "check" token used to detect a wrong master
password before it's mistaken for a fresh one and silently used to encrypt
new entries under a different key.
"""

from __future__ import annotations

import base64
import json
import secrets
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_PBKDF2_ITERATIONS = 480_000
_CHECK_PLAINTEXT = b"atalaya-vault-check-v1"
DEFAULT_VAULT_PATH = Path.home() / ".atalaya" / "vault.json"


class WrongMasterPassword(ValueError):
    pass


class VaultNotInitialized(RuntimeError):
    pass


@dataclass
class HistoryEntry:
    id: str
    created_at: str
    site: str
    username: str
    encrypted_password: str
    bits: float
    label: str
    mode: str

    def to_dict(self) -> dict:
        return asdict(self)


def _derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


class Vault:
    def __init__(self, path: Path = DEFAULT_VAULT_PATH):
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists()

    def _load_raw(self) -> dict:
        if not self.exists():
            return {"salt": None, "check": None, "entries": []}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save_raw(self, raw: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

    def _get_or_create_salt(self, raw: dict) -> bytes:
        if raw.get("salt"):
            return base64.urlsafe_b64decode(raw["salt"])
        salt = secrets.token_bytes(16)
        raw["salt"] = base64.urlsafe_b64encode(salt).decode("ascii")
        return salt

    def _verify_or_register_key(self, raw: dict, key: bytes) -> None:
        if not raw.get("check"):
            raw["check"] = Fernet(key).encrypt(_CHECK_PLAINTEXT).decode("ascii")
            return
        try:
            Fernet(key).decrypt(raw["check"].encode("ascii"))
        except InvalidToken as exc:
            raise WrongMasterPassword("contrasena maestra incorrecta") from exc

    def add_entry(
        self,
        master_password: str,
        *,
        site: str,
        username: str,
        password: str,
        bits: float,
        label: str,
        mode: str,
    ) -> HistoryEntry:
        raw = self._load_raw()
        salt = self._get_or_create_salt(raw)
        key = _derive_key(master_password, salt)
        self._verify_or_register_key(raw, key)

        entry = HistoryEntry(
            id=uuid.uuid4().hex,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            site=site,
            username=username,
            encrypted_password=Fernet(key).encrypt(password.encode("utf-8")).decode("ascii"),
            bits=bits,
            label=label,
            mode=mode,
        )
        raw.setdefault("entries", []).append(entry.to_dict())
        self._save_raw(raw)
        return entry

    def list_entries(self) -> list[HistoryEntry]:
        raw = self._load_raw()
        return [HistoryEntry(**item) for item in raw.get("entries", [])]

    def reveal(self, entry_id: str, master_password: str) -> str:
        raw = self._load_raw()
        salt_b64 = raw.get("salt")
        if not salt_b64:
            raise VaultNotInitialized("no hay historial guardado todavia")

        salt = base64.urlsafe_b64decode(salt_b64)
        key = _derive_key(master_password, salt)
        self._verify_or_register_key(raw, key)

        entry = next((e for e in raw.get("entries", []) if e["id"] == entry_id), None)
        if entry is None:
            raise KeyError(entry_id)

        return Fernet(key).decrypt(entry["encrypted_password"].encode("ascii")).decode("utf-8")

    def delete(self, entry_id: str) -> None:
        raw = self._load_raw()
        raw["entries"] = [e for e in raw.get("entries", []) if e["id"] != entry_id]
        self._save_raw(raw)

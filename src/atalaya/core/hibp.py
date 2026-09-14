"""Breach lookup against Have I Been Pwned using k-anonymity.

The password itself never leaves the machine. We SHA-1 hash it locally,
send only the first 5 hex characters of that hash to the API, and the
service replies with every suffix on record sharing that prefix (plus how
many times each has been seen). The match is then done locally against that
list. HIBP documents this scheme at
https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass

_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_USER_AGENT = "atalaya-password-generator"


@dataclass(frozen=True)
class PwnedResult:
    checked: bool
    times_seen: int
    error: str | None = None

    @property
    def is_pwned(self) -> bool:
        return self.checked and self.times_seen > 0


class HibpLookupError(RuntimeError):
    pass


def _sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_password(password: str, *, timeout: float = 6.0) -> PwnedResult:
    digest = _sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]

    request = urllib.request.Request(
        _API_URL.format(prefix=prefix),
        headers={"User-Agent": _USER_AGENT, "Add-Padding": "true"},
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as exc:
        return PwnedResult(checked=False, times_seen=0, error=str(exc))

    for line in body.splitlines():
        candidate_suffix, _, count = line.partition(":")
        if candidate_suffix.strip() == suffix:
            return PwnedResult(checked=True, times_seen=int(count.strip() or 0))

    return PwnedResult(checked=True, times_seen=0)

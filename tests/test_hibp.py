from unittest.mock import patch

from atalaya.core import hibp


def _fake_response(body: str):
    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return body.encode("utf-8")

    return _Resp()


def test_sha1_hex_is_uppercase_and_correct_length():
    digest = hibp._sha1_hex("correct horse battery staple")
    assert len(digest) == 40
    assert digest == digest.upper()


def test_only_prefix_leaves_the_machine():
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        return _fake_response("0000000000000000000000000000000000:3\r\n")

    with patch("atalaya.core.hibp.urllib.request.urlopen", side_effect=fake_urlopen):
        hibp.check_password("hunter2")

    digest = hibp._sha1_hex("hunter2")
    assert digest[:5] in captured["url"]
    assert digest[5:] not in captured["url"]


def test_match_found_reports_count():
    digest = hibp._sha1_hex("password")
    suffix = digest[5:]
    body = f"{suffix}:3730471\r\nAAAAA:1\r\n"

    with patch("atalaya.core.hibp.urllib.request.urlopen", return_value=_fake_response(body)):
        result = hibp.check_password("password")

    assert result.is_pwned
    assert result.times_seen == 3730471


def test_no_match_reports_clean():
    body = "AAAAA:1\r\nBBBBB:2\r\n"
    with patch("atalaya.core.hibp.urllib.request.urlopen", return_value=_fake_response(body)):
        result = hibp.check_password("a very unusual passphrase indeed")
    assert result.checked
    assert not result.is_pwned


def test_network_error_is_reported_not_raised():
    import urllib.error

    with patch(
        "atalaya.core.hibp.urllib.request.urlopen",
        side_effect=urllib.error.URLError("no network"),
    ):
        result = hibp.check_password("whatever")

    assert not result.checked
    assert result.error is not None

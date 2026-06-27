"""Unit tests for HMAC-signed session tokens (F4)."""

from pyhttpd.domain.sessions import sign, verify

SECRET = "topsecret"


def test_sign_verify_round_trip() -> None:
    token = sign("abc123", SECRET)
    assert verify(token, SECRET) == "abc123"


def test_verify_rejects_tampered_id() -> None:
    _, _, signature = sign("abc123", SECRET).rpartition(".")
    assert verify(f"abc124.{signature}", SECRET) is None


def test_verify_rejects_wrong_secret() -> None:
    token = sign("abc123", SECRET)
    assert verify(token, "othersecret") is None


def test_verify_rejects_missing_signature() -> None:
    assert verify("abc123", SECRET) is None


def test_verify_rejects_empty_id() -> None:
    assert verify(".somesig", SECRET) is None

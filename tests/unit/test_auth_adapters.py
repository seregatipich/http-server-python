"""Unit tests for the api-key and JWT authentication adapters."""

import base64
import hashlib
import hmac
import json

import pytest

from pyhttpd.adapters.auth import (
    ApiKeyAuthenticator,
    JwtAuthenticator,
    decode_hs256,
)
from pyhttpd.adapters.auth.jwt import InvalidToken
from pyhttpd.domain import AuthConfig

SECRET = "topsecret"


def _b64(segment: bytes) -> str:
    return base64.urlsafe_b64encode(segment).rstrip(b"=").decode("ascii")


def _encode(payload, secret=SECRET, header=None):
    header = header or {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        _b64(json.dumps(header).encode()) + "." + _b64(json.dumps(payload).encode())
    )
    signature = hmac.new(
        secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    return signing_input + "." + _b64(signature)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def test_decode_hs256_accepts_a_valid_token():
    """A correctly signed, unexpired token decodes to its claims."""
    token = _encode({"sub": "reader", "exp": 4102444800})
    claims = decode_hs256(token, SECRET, now=1000)
    assert claims["sub"] == "reader"


def test_decode_hs256_rejects_a_tampered_signature():
    """A token signed with the wrong secret is rejected."""
    token = _encode({"sub": "reader", "exp": 4102444800}, secret="wrong")
    with pytest.raises(InvalidToken):
        decode_hs256(token, SECRET, now=1000)


def test_decode_hs256_rejects_non_hs256_alg():
    """Tokens declaring alg=none or another algorithm are rejected."""
    token = _encode({"sub": "reader", "exp": 4102444800}, header={"alg": "none"})
    with pytest.raises(InvalidToken):
        decode_hs256(token, SECRET, now=1000)


def test_decode_hs256_rejects_malformed_token():
    """A token without three segments is rejected."""
    with pytest.raises(InvalidToken):
        decode_hs256("not.a.valid.jwt.token", SECRET, now=1000)


def test_decode_hs256_rejects_non_utf8_payload():
    """A correctly signed but non-UTF-8 payload yields InvalidToken, not a crash."""
    header_segment = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_segment = _b64(b"\x80\x81\x82\x83")
    signing_input = f"{header_segment}.{payload_segment}"
    signature = _b64(
        hmac.new(SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    )
    with pytest.raises(InvalidToken):
        decode_hs256(f"{signing_input}.{signature}", SECRET, now=1000)


def test_decode_hs256_rejects_non_finite_exp():
    """An Infinity exp must be rejected, not treated as a never-expiring token."""
    token = _encode({"sub": "reader", "exp": float("inf")})
    with pytest.raises(InvalidToken):
        decode_hs256(token, SECRET, now=1000)


def test_decode_hs256_requires_exp_and_rejects_expired():
    """Expired tokens and tokens missing exp are rejected."""
    expired = _encode({"sub": "reader", "exp": 500})
    with pytest.raises(InvalidToken):
        decode_hs256(expired, SECRET, now=1000)
    no_exp = _encode({"sub": "reader"})
    with pytest.raises(InvalidToken):
        decode_hs256(no_exp, SECRET, now=1000)


def test_decode_hs256_honors_nbf():
    """A token whose not-before is in the future is rejected."""
    token = _encode({"sub": "reader", "exp": 4102444800, "nbf": 2000})
    with pytest.raises(InvalidToken):
        decode_hs256(token, SECRET, now=1000)


def test_decode_hs256_validates_issuer():
    """A token whose issuer mismatches the expected issuer is rejected."""
    token = _encode({"sub": "reader", "exp": 4102444800, "iss": "evil"})
    with pytest.raises(InvalidToken):
        decode_hs256(token, SECRET, issuer="pyhttpd", now=1000)
    ok = _encode({"sub": "reader", "exp": 4102444800, "iss": "pyhttpd"})
    assert decode_hs256(ok, SECRET, issuer="pyhttpd", now=1000)["iss"] == "pyhttpd"


def test_decode_hs256_validates_audience_string_and_list():
    """Audience is checked against a string claim or a list claim."""
    string_aud = _encode({"sub": "reader", "exp": 4102444800, "aud": "api"})
    assert decode_hs256(string_aud, SECRET, audience="api", now=1000)["sub"] == "reader"
    list_aud = _encode({"sub": "reader", "exp": 4102444800, "aud": ["web", "api"]})
    assert decode_hs256(list_aud, SECRET, audience="api", now=1000)["sub"] == "reader"
    wrong = _encode({"sub": "reader", "exp": 4102444800, "aud": "web"})
    with pytest.raises(InvalidToken):
        decode_hs256(wrong, SECRET, audience="api", now=1000)


def test_api_key_authenticator_accepts_a_known_key():
    """A presented key matching a stored hash yields its principal."""
    config = AuthConfig(
        mode="api-key",
        credentials={"reader": _sha256_hex("s3cret")},
        roles={"reader": ["files:read"]},
    )
    authenticator = ApiKeyAuthenticator(config)
    principal = authenticator.authenticate({"authorization": "ApiKey s3cret"})
    assert principal is not None
    assert principal.identity == "reader"
    assert principal.has_scope("files:read")


def test_api_key_authenticator_rejects_unknown_key():
    """A presented key with no matching hash fails authentication."""
    config = AuthConfig(
        mode="api-key",
        credentials={"reader": _sha256_hex("s3cret")},
        roles={"reader": ["files:read"]},
    )
    authenticator = ApiKeyAuthenticator(config)
    assert authenticator.authenticate({"authorization": "ApiKey wrong"}) is None


def test_api_key_authenticator_rejects_missing_or_wrong_scheme():
    """Absent or non-ApiKey Authorization headers fail authentication."""
    config = AuthConfig(mode="api-key", credentials={}, roles={})
    authenticator = ApiKeyAuthenticator(config)
    assert authenticator.authenticate({}) is None
    assert authenticator.authenticate({"authorization": "Bearer x"}) is None


def test_api_key_authenticator_accepts_case_insensitive_scheme():
    """The auth scheme token is matched case-insensitively per RFC 7235."""
    config = AuthConfig(
        mode="api-key",
        credentials={"reader": _sha256_hex("s3cret")},
        roles={"reader": ["files:read"]},
    )
    authenticator = ApiKeyAuthenticator(config)
    assert authenticator.authenticate({"authorization": "apikey s3cret"}) is not None
    assert authenticator.authenticate({"authorization": "APIKEY s3cret"}) is not None


def test_api_key_authenticator_challenge():
    """The api-key challenge advertises the ApiKey scheme."""
    authenticator = ApiKeyAuthenticator(AuthConfig(mode="api-key"))
    assert authenticator.challenge == 'ApiKey realm="pyhttpd"'


def test_jwt_authenticator_accepts_valid_token_with_scopes():
    """A valid Bearer token maps its subject and scopes to a principal."""
    config = AuthConfig(mode="jwt", jwt_secret=SECRET)
    authenticator = JwtAuthenticator(config, now=lambda: 1000)
    token = _encode(
        {"sub": "writer", "exp": 4102444800, "scope": "files:read files:write"}
    )
    principal = authenticator.authenticate({"authorization": f"Bearer {token}"})
    assert principal is not None
    assert principal.identity == "writer"
    assert principal.has_scope("files:write")


def test_jwt_authenticator_rejects_invalid_token():
    """An invalid or wrongly-schemed token fails authentication."""
    config = AuthConfig(mode="jwt", jwt_secret=SECRET)
    authenticator = JwtAuthenticator(config, now=lambda: 1000)
    bad = _encode({"sub": "x", "exp": 4102444800}, secret="wrong")
    assert authenticator.authenticate({"authorization": f"Bearer {bad}"}) is None
    assert authenticator.authenticate({"authorization": "ApiKey foo"}) is None


def test_jwt_authenticator_challenge():
    """The JWT challenge advertises the Bearer scheme."""
    authenticator = JwtAuthenticator(AuthConfig(mode="jwt", jwt_secret=SECRET))
    assert authenticator.challenge == 'Bearer realm="pyhttpd"'

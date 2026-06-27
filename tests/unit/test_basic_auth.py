"""Unit tests for the HTTP Basic authentication adapter (F5)."""

import base64
import hashlib

from pyhttpd.adapters.auth.basic import BasicAuthenticator
from pyhttpd.domain import AuthConfig


def _basic_header(identity: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{identity}:{password}".encode()).decode()
    return {"authorization": f"Basic {token}"}


def _config() -> AuthConfig:
    return AuthConfig(
        mode="basic",
        credentials={"alice": hashlib.sha256(b"s3cret").hexdigest()},
        roles={"alice": ["files:read"]},
    )


def test_challenge_is_basic_realm() -> None:
    assert BasicAuthenticator(_config()).challenge == 'Basic realm="pyhttpd"'


def test_valid_credentials_resolve_principal() -> None:
    principal = BasicAuthenticator(_config()).authenticate(
        _basic_header("alice", "s3cret")
    )
    assert principal is not None
    assert principal.identity == "alice"
    assert principal.has_scope("files:read")


def test_wrong_password_rejected() -> None:
    assert (
        BasicAuthenticator(_config()).authenticate(_basic_header("alice", "wrong"))
        is None
    )


def test_unknown_identity_rejected() -> None:
    assert (
        BasicAuthenticator(_config()).authenticate(_basic_header("mallory", "s3cret"))
        is None
    )


def test_missing_header_returns_none() -> None:
    assert BasicAuthenticator(_config()).authenticate({}) is None


def test_non_basic_scheme_ignored() -> None:
    assert (
        BasicAuthenticator(_config()).authenticate({"authorization": "Bearer x"})
        is None
    )


def test_malformed_base64_rejected() -> None:
    assert (
        BasicAuthenticator(_config()).authenticate(
            {"authorization": "Basic not!base64"}
        )
        is None
    )


def test_credentials_without_colon_rejected() -> None:
    token = base64.b64encode(b"no-colon").decode()
    assert (
        BasicAuthenticator(_config()).authenticate({"authorization": f"Basic {token}"})
        is None
    )

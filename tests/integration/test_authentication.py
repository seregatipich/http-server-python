"""Integration tests for authentication and authorization."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import TYPE_CHECKING

import pytest
import requests

from tests.conftest import JWT_SECRET, READER_KEY, WRITER_KEY

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo


def _b64(segment: bytes) -> str:
    return base64.urlsafe_b64encode(segment).rstrip(b"=").decode("ascii")


def _make_jwt(claims: dict, secret: str = JWT_SECRET) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        _b64(json.dumps(header).encode()) + "." + _b64(json.dumps(claims).encode())
    )
    signature = hmac.new(
        secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    return signing_input + "." + _b64(signature)


def test_missing_credentials_returns_401_with_challenge(
    authed_server_process: "ServerProcessInfo",
) -> None:
    """A request to a protected path without credentials is rejected with 401."""
    base_url = authed_server_process["base_url"]
    response = requests.get(f"{base_url}/files/missing.txt", timeout=5)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == 'ApiKey realm="pyhttpd"'


def test_wrong_credentials_returns_401(
    authed_server_process: "ServerProcessInfo",
) -> None:
    """An unrecognized api key is rejected with 401."""
    base_url = authed_server_process["base_url"]
    response = requests.get(
        f"{base_url}/files/missing.txt",
        headers={"Authorization": "ApiKey bogus"},
        timeout=5,
    )
    assert response.status_code == 401


def test_reader_can_get_files(authed_server_process: "ServerProcessInfo") -> None:
    """A reader principal with files:read may GET the files endpoint."""
    base_url = authed_server_process["base_url"]
    response = requests.get(
        f"{base_url}/files/missing.txt",
        headers={"Authorization": f"ApiKey {READER_KEY}"},
        timeout=5,
    )
    assert response.status_code == 404


def test_reader_cannot_post_files(authed_server_process: "ServerProcessInfo") -> None:
    """A reader lacking files:write is forbidden from POSTing."""
    base_url = authed_server_process["base_url"]
    response = requests.post(
        f"{base_url}/files/new.txt",
        headers={"Authorization": f"ApiKey {READER_KEY}"},
        data=b"payload",
        timeout=5,
    )
    assert response.status_code == 403


def test_writer_can_post_files(authed_server_process: "ServerProcessInfo") -> None:
    """A writer principal with files:write may POST to the files endpoint."""
    base_url = authed_server_process["base_url"]
    response = requests.post(
        f"{base_url}/files/created.txt",
        headers={"Authorization": f"ApiKey {WRITER_KEY}"},
        data=b"payload",
        timeout=5,
    )
    assert response.status_code == 201


def test_healthz_is_public(authed_server_process: "ServerProcessInfo") -> None:
    """The health endpoint stays reachable without credentials."""
    base_url = authed_server_process["base_url"]
    response = requests.get(f"{base_url}/healthz", timeout=5)
    assert response.status_code == 200


def test_cors_preflight_bypasses_auth(
    authed_server_process: "ServerProcessInfo",
) -> None:
    """A CORS preflight request is answered without authentication."""
    base_url = authed_server_process["base_url"]
    response = requests.options(
        f"{base_url}/files/any.txt",
        headers={
            "Origin": "http://example.com",
            "Access-Control-Request-Method": "GET",
        },
        timeout=5,
    )
    assert response.status_code != 401


def test_valid_jwt_grants_access(jwt_server_process: "ServerProcessInfo") -> None:
    """A signed, unexpired JWT with files:read scope is accepted."""
    base_url = jwt_server_process["base_url"]
    token = _make_jwt(
        {"sub": "alice", "exp": int(time.time()) + 3600, "scope": "files:read"}
    )
    response = requests.get(
        f"{base_url}/files/missing.txt",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert response.status_code == 404


def test_forged_jwt_is_rejected(jwt_server_process: "ServerProcessInfo") -> None:
    """A JWT signed with the wrong secret is rejected with 401."""
    base_url = jwt_server_process["base_url"]
    token = _make_jwt(
        {"sub": "mallory", "exp": int(time.time()) + 3600, "scope": "files:read"},
        secret="wrong-secret",
    )
    response = requests.get(
        f"{base_url}/files/missing.txt",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == 'Bearer realm="pyhttpd"'

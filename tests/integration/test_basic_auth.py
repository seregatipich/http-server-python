"""Integration tests for HTTP Basic authentication (F5)."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest
import requests

from tests.conftest import BASIC_PASSWORD, BASIC_USER

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo


def _basic_header(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_missing_credentials_returns_401_with_basic_challenge(
    basic_auth_server_process: "ServerProcessInfo",
) -> None:
    base_url = basic_auth_server_process["base_url"]
    response = requests.get(f"{base_url}/files/missing.txt", timeout=5)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == 'Basic realm="pyhttpd"'


def test_wrong_password_returns_401(
    basic_auth_server_process: "ServerProcessInfo",
) -> None:
    base_url = basic_auth_server_process["base_url"]
    response = requests.get(
        f"{base_url}/files/missing.txt",
        headers=_basic_header(BASIC_USER, "wrong"),
        timeout=5,
    )
    assert response.status_code == 401


def test_valid_credentials_allow_read(
    basic_auth_server_process: "ServerProcessInfo",
) -> None:
    base_url = basic_auth_server_process["base_url"]
    response = requests.get(
        f"{base_url}/files/missing.txt",
        headers=_basic_header(BASIC_USER, BASIC_PASSWORD),
        timeout=5,
    )
    assert response.status_code == 404  # authenticated, but the file does not exist


def test_read_only_identity_forbidden_from_write(
    basic_auth_server_process: "ServerProcessInfo",
) -> None:
    base_url = basic_auth_server_process["base_url"]
    response = requests.post(
        f"{base_url}/files/new.txt",
        headers=_basic_header(BASIC_USER, BASIC_PASSWORD),
        data=b"payload",
        timeout=5,
    )
    assert response.status_code == 403

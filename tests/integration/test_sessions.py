"""Integration tests for signed session cookies (F4)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import requests

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo


def test_new_visitor_receives_session_cookie(
    session_server_process: "ServerProcessInfo",
) -> None:
    response = requests.get(f"{session_server_process['base_url']}/healthz", timeout=5)
    cookie = response.headers.get("Set-Cookie", "")
    assert cookie.startswith("session=")
    assert "HttpOnly" in cookie
    assert "Path=/" in cookie


def test_returning_visitor_not_reissued(
    session_server_process: "ServerProcessInfo",
) -> None:
    base_url = session_server_process["base_url"]
    client = requests.Session()
    first = client.get(f"{base_url}/healthz", timeout=5)
    assert "Set-Cookie" in first.headers
    second = client.get(f"{base_url}/healthz", timeout=5)
    assert "Set-Cookie" not in second.headers


def test_tampered_cookie_is_reissued(
    session_server_process: "ServerProcessInfo",
) -> None:
    base_url = session_server_process["base_url"]
    response = requests.get(
        f"{base_url}/healthz",
        headers={"Cookie": "session=forged.signature"},
        timeout=5,
    )
    assert response.headers.get("Set-Cookie", "").startswith("session=")


def test_sessions_disabled_by_default(server_process: "ServerProcessInfo") -> None:
    response = requests.get(f"{server_process['base_url']}/healthz", timeout=5)
    assert "Set-Cookie" not in response.headers

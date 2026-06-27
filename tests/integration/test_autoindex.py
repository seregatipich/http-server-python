"""Integration tests for the directory autoindex (F10)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import requests

from tests.characterization.raw_client import send_raw

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo


def test_autoindex_lists_directory(autoindex_server: "ServerProcessInfo") -> None:
    response = requests.get(f"{autoindex_server['base_url']}/files/docs/", timeout=5)
    assert response.status_code == 200
    assert "text/html" in response.headers["Content-Type"]
    assert "readme.txt" in response.text
    assert "data.bin" in response.text


def test_autoindex_traversal_still_blocked(
    autoindex_server: "ServerProcessInfo",
) -> None:
    raw = send_raw(
        autoindex_server["host"],
        autoindex_server["port"],
        b"GET /files/../etc HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    status_line = raw.split(b"\r\n", 1)[0]
    assert status_line == b"HTTP/1.1 403 Forbidden"


def test_directory_404_without_autoindex(server_process: "ServerProcessInfo") -> None:
    directory = server_process["directory"]
    (directory / "sub").mkdir()
    response = requests.get(f"{server_process['base_url']}/files/sub", timeout=5)
    assert response.status_code == 404

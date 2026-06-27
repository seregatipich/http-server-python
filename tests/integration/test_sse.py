"""Integration tests for the Server-Sent Events endpoint (F6)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import requests

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo


def test_sse_stream_delivers_events(sse_server_process: "ServerProcessInfo") -> None:
    response = requests.get(
        f"{sse_server_process['base_url']}/events?count=3", timeout=10
    )
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "text/event-stream"
    assert response.headers["Cache-Control"] == "no-cache"
    body = response.text
    assert body.count("event: tick") == 3
    assert "data: 1" in body
    assert "data: 3" in body


def test_sse_rejects_post(sse_server_process: "ServerProcessInfo") -> None:
    response = requests.post(f"{sse_server_process['base_url']}/events", timeout=5)
    assert response.status_code == 405


def test_sse_disabled_by_default(server_process: "ServerProcessInfo") -> None:
    response = requests.get(f"{server_process['base_url']}/events", timeout=5)
    assert response.status_code == 404

"""Integration tests for connection and rate limiting."""

from __future__ import annotations

import socket

import pytest
import requests

from tests.utils.http import read_http_response

pytestmark = pytest.mark.integration


def test_connection_limit_returns_503(limited_server_process) -> None:
    """When the connection cap is exceeded the server should respond with 503."""
    host = limited_server_process["host"]
    port = limited_server_process["port"]

    holder = socket.create_connection((host, port), timeout=2)
    try:
        with socket.create_connection((host, port), timeout=2) as blocked:
            response = read_http_response(blocked)
        assert response.status_line.startswith("HTTP/1.1 503")
        assert b"connection limit exceeded" in response.body
    finally:
        holder.close()


def test_rate_limit_returns_429_and_headers(limited_server_process) -> None:
    """Rate limiter should respond with 429 and the standard RateLimit headers."""
    base_url = limited_server_process["base_url"]

    with requests.Session() as session:
        first = session.get(f"{base_url}/", timeout=5)
        second = session.get(f"{base_url}/", timeout=5)
        assert first.status_code == 200
        assert second.status_code == 200

        limited = session.get(f"{base_url}/", timeout=5)

    assert limited.status_code == 429
    headers = limited.headers
    assert headers.get("RateLimit-Limit") == "2"
    assert headers.get("RateLimit-Remaining") == "0"
    assert headers.get("Retry-After") == "1"
    assert headers.get("RateLimit-Reset") is not None
    assert limited.content == b"Rate limit exceeded"

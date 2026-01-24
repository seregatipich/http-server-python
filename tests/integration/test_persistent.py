from __future__ import annotations

import socket

import pytest

from tests.utils.http import read_http_response

pytestmark = pytest.mark.integration


def build_request(path: str, host: str, port: int, connection: str | None = None) -> bytes:
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
    ]
    if connection:
        lines.append(f"Connection: {connection}")
    lines.extend(["", ""])
    return "\r\n".join(lines).encode()


def test_multiple_requests_share_connection(server_process):
    host = server_process["host"]
    port = server_process["port"]

    with socket.create_connection((host, port), timeout=5) as client:
        client.sendall(build_request("/echo/first", host, port))
        first = read_http_response(client)
        assert b"first" in first.body

        client.sendall(build_request("/echo/second", host, port))
        second = read_http_response(client)
        assert b"second" in second.body

        client.sendall(build_request("/echo/final", host, port, connection="close"))
        final = read_http_response(client)
        assert b"final" in final.body

        client.settimeout(1)
        remaining = client.recv(1)
        assert remaining == b""

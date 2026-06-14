"""Minimal raw-socket HTTP client for characterizing error paths."""

from __future__ import annotations

import socket


def send_raw(host: str, port: int, request: bytes, timeout: float = 5.0) -> bytes:
    """Send raw request bytes and return the full raw response."""

    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.sendall(request)
        chunks: list[bytes] = []
        while True:
            received = connection.recv(4096)
            if not received:
                break
            chunks.append(received)
        return b"".join(chunks)


def status_line(raw_response: bytes) -> str:
    """Extract the status line from a raw HTTP response."""

    return raw_response.split(b"\r\n", 1)[0].decode("latin-1")

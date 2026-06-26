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


def parse_response(raw_response: bytes) -> tuple[str, dict[str, str], bytes]:
    """Split a raw HTTP response into status line, header map, and body bytes."""

    header_block, body = raw_response.split(b"\r\n\r\n", 1)
    lines = header_block.split(b"\r\n")
    status = lines[0].decode("latin-1")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, _, value = line.partition(b": ")
        headers[name.decode("latin-1")] = value.decode("latin-1")
    return status, headers, body

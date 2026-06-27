"""Minimal raw-socket WebSocket client for integration tests."""

from __future__ import annotations

import base64
import os
import socket
import struct
from typing import Tuple


def open_connection(
    host: str, port: int, path: str = "/ws", timeout: float = 5.0
) -> Tuple[socket.socket, bytes, str]:
    """Perform the opening handshake; return (socket, raw_response, sent_key)."""
    sock = socket.create_connection((host, port), timeout=timeout)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n\r\n"
    ).encode()
    sock.sendall(request)
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    return sock, response, key


def send(sock: socket.socket, opcode: int, payload: bytes) -> None:
    """Send a masked client frame (clients MUST mask per RFC 6455)."""
    mask = os.urandom(4)
    masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    first = 0x80 | opcode
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", first, 0x80 | length)
    elif length < (1 << 16):
        header = struct.pack("!BBH", first, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", first, 0x80 | 127, length)
    sock.sendall(header + mask + masked)


def recv(sock: socket.socket) -> Tuple[int, bytes]:
    """Read one unmasked server frame; return (opcode, payload)."""
    header = _recv_exact(sock, 2)
    opcode = header[0] & 0x0F
    length = header[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(sock, 8))[0]
    payload = _recv_exact(sock, length) if length else b""
    return opcode, payload


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buffer = b""
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            raise ConnectionError("connection closed mid-frame")
        buffer += chunk
    return buffer

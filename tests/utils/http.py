from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

HEADER_DELIMITER = b"\r\n\r\n"
CRLF = b"\r\n"


@dataclass(slots=True)
class RawHttpResponse:
    status_line: str
    headers: Dict[str, str]
    body: bytes
    chunk_sizes: Optional[List[int]] = None


def reserve_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Server did not start on {host}:{port} within {timeout}s")


def read_http_response(sock: socket.socket) -> RawHttpResponse:
    buffer = b""
    while HEADER_DELIMITER not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed before headers were received")
        buffer += chunk
    header_block, remainder = buffer.split(HEADER_DELIMITER, 1)
    header_lines = header_block.decode().split("\r\n")
    status_line = header_lines[0]
    headers = _parse_headers(header_lines[1:])
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if transfer_encoding == "chunked":
        body, chunk_sizes = _read_chunked_body(sock, remainder)
        return RawHttpResponse(status_line, headers, body, chunk_sizes)
    content_length = int(headers.get("content-length", "0"))
    body = _read_fixed_body(sock, remainder, content_length)
    return RawHttpResponse(status_line, headers, body)


def _parse_headers(lines: List[str]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for line in lines:
        if not line:
            continue
        if ": " not in line:
            continue
        name, value = line.split(": ", 1)
        parsed[name.lower()] = value
    return parsed


def _read_fixed_body(sock: socket.socket, buffer: bytes, length: int) -> bytes:
    data = buffer
    while len(data) < length:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed before body completed")
        data += chunk
    return data[:length]


def _read_chunked_body(sock: socket.socket, buffer: bytes) -> tuple[bytes, List[int]]:
    chunks: List[bytes] = []
    sizes: List[int] = []
    remaining = buffer
    while True:
        while CRLF not in remaining:
            chunk = sock.recv(4096)
            if not chunk:
                raise RuntimeError("Connection closed before chunk size received")
            remaining += chunk
        size_line, remaining = remaining.split(CRLF, 1)
        size = int(size_line.decode(), 16)
        sizes.append(size)
        if size == 0:
            remaining = _consume_trailing_crlf(sock, remaining)
            break
        while len(remaining) < size + len(CRLF):
            chunk = sock.recv(4096)
            if not chunk:
                raise RuntimeError("Connection closed before chunk completed")
            remaining += chunk
        chunk_data, remaining = remaining[:size], remaining[size + len(CRLF) :]
        chunks.append(chunk_data)
    body = b"".join(chunks)
    return body, sizes


def _consume_trailing_crlf(sock: socket.socket, buffer: bytes) -> bytes:
    data = buffer
    while len(data) < len(CRLF):
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed before terminating CRLF")
        data += chunk
    return data[len(CRLF) :]

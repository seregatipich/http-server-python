"""Integration tests covering sandboxed file handling and validation."""

import socket
from typing import TYPE_CHECKING

import pytest

from tests.utils.http import RawHttpResponse, read_http_response

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo

pytestmark = pytest.mark.integration


def _send_raw_request(host: str, port: int, request_bytes: bytes) -> RawHttpResponse:
    """Send raw bytes to the server and capture the parsed response."""
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(request_bytes)
        return read_http_response(sock)


def test_forbid_directory_traversal_get(
    server_process: "ServerProcessInfo",
) -> None:
    """Reject GET traversal attempts in the sandbox."""
    host, port = server_process["host"], server_process["port"]
    raw_request = b"GET /files/../etc/passwd HTTP/1.1\r\nHost: test\r\n\r\n"
    response = _send_raw_request(host, port, raw_request)
    assert response.status_line.startswith("HTTP/1.1 403")


def test_forbid_directory_traversal_post(
    server_process: "ServerProcessInfo",
) -> None:
    """Reject POST traversal attempts in the sandbox."""
    host, port = server_process["host"], server_process["port"]
    body = b"payload"
    raw_request = (
        b"POST /files/../etc/passwd HTTP/1.1\r\n"
        b"Host: test\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    response = _send_raw_request(host, port, raw_request)
    assert response.status_line.startswith("HTTP/1.1 403")


def test_forbid_empty_filename(
    server_process: "ServerProcessInfo",
) -> None:
    """Reject empty filenames under the files endpoint."""
    host, port = server_process["host"], server_process["port"]
    raw_request = b"GET /files/ HTTP/1.1\r\nHost: test\r\n\r\n"
    response = _send_raw_request(host, port, raw_request)
    assert response.status_line.startswith("HTTP/1.1 403")

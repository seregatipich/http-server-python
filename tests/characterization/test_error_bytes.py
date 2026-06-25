"""Golden byte-level pins for the server's error responses prior to a rewrite."""

from __future__ import annotations

import re
import socket
import time

import pytest

from tests.characterization.raw_client import send_raw

pytestmark = pytest.mark.integration

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
}

REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]+$")
RATE_LIMIT_RESET_PATTERN = re.compile(r"^\d+(\.\d+)?$")


def parse_response(raw_response: bytes) -> tuple[str, dict[str, str], bytes]:
    """Split a raw HTTP response into status line, header map, and body bytes."""

    header_block, body = raw_response.split(b"\r\n\r\n", 1)
    lines = header_block.split(b"\r\n")
    status_line = lines[0].decode("latin-1")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, _, value = line.partition(b": ")
        headers[name.decode("latin-1")] = value.decode("latin-1")
    return status_line, headers, body


def assert_request_id(headers: dict[str, str]) -> None:
    """Pin the X-Request-ID header by presence and shape, never its value."""

    assert "X-Request-ID" in headers
    assert REQUEST_ID_PATTERN.match(headers["X-Request-ID"])


def assert_security_headers(headers: dict[str, str]) -> None:
    """Pin the baseline security headers by exact name and value."""

    for name, expected in SECURITY_HEADERS.items():
        assert headers[name] == expected


def test_bad_request_400_bytes(server_process) -> None:
    """A malformed request line yields an empty-bodied 400 with security headers."""

    raw = send_raw(
        server_process["host"],
        server_process["port"],
        b"GET\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 400 Bad Request"
    assert_security_headers(headers)
    assert_request_id(headers)
    assert headers["Content-Length"] == "0"
    assert headers["Connection"] == "close"
    assert "Access-Control-Allow-Origin" not in headers
    assert set(headers) == {
        *SECURITY_HEADERS,
        "X-Request-ID",
        "Content-Length",
        "Connection",
    }
    assert body == b""


def test_forbidden_403_bytes(server_process) -> None:
    """Path traversal through /files yields an empty-bodied 403 with security headers."""

    raw = send_raw(
        server_process["host"],
        server_process["port"],
        b"GET /files/../secret HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 403 Forbidden"
    assert_security_headers(headers)
    assert_request_id(headers)
    assert headers["Content-Length"] == "0"
    assert headers["Connection"] == "close"
    assert set(headers) == {
        *SECURITY_HEADERS,
        "X-Request-ID",
        "Content-Length",
        "Connection",
    }
    assert body == b""


def test_unauthorized_401_bytes(authed_server_process) -> None:
    """A protected path without credentials yields a 401 with a challenge header."""

    raw = send_raw(
        authed_server_process["host"],
        authed_server_process["port"],
        b"GET /files/secret.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 401 Unauthorized"
    assert headers["WWW-Authenticate"] == 'ApiKey realm="pyhttpd"'
    assert_security_headers(headers)
    assert_request_id(headers)
    assert headers["Content-Length"] == "0"
    assert headers["Connection"] == "close"
    assert "Access-Control-Allow-Origin" not in headers
    assert set(headers) == {
        "WWW-Authenticate",
        *SECURITY_HEADERS,
        "X-Request-ID",
        "Content-Length",
        "Connection",
    }
    assert body == b""


def test_not_found_404_bytes(server_process) -> None:
    """An unknown route yields a 404 carrying default rate-limit headers."""

    raw = send_raw(
        server_process["host"],
        server_process["port"],
        b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 404 Not Found"
    assert_security_headers(headers)
    assert_request_id(headers)
    assert headers["RateLimit-Limit"] == "50"
    assert headers["RateLimit-Remaining"].isdigit()
    assert RATE_LIMIT_RESET_PATTERN.match(headers["RateLimit-Reset"])
    assert headers["Content-Length"] == "0"
    assert headers["Connection"] == "close"
    assert set(headers) == {
        *SECURITY_HEADERS,
        "RateLimit-Limit",
        "RateLimit-Remaining",
        "RateLimit-Reset",
        "X-Request-ID",
        "Content-Length",
        "Connection",
    }
    assert body == b""


def test_method_not_allowed_405_bytes(server_process) -> None:
    """A disallowed method yields a 405 enumerating the supported methods."""

    raw = send_raw(
        server_process["host"],
        server_process["port"],
        b"DELETE /echo/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 405 Method Not Allowed"
    assert headers["Allow"] == "GET, OPTIONS, POST"
    assert_security_headers(headers)
    assert_request_id(headers)
    assert headers["Content-Length"] == "0"
    assert headers["Connection"] == "close"
    assert set(headers) == {
        "Allow",
        *SECURITY_HEADERS,
        "X-Request-ID",
        "Content-Length",
        "Connection",
    }
    assert body == b""


def test_payload_too_large_413_bytes(server_process) -> None:
    """A declared body beyond the limit yields an empty-bodied 413 that closes."""

    raw = send_raw(
        server_process["host"],
        server_process["port"],
        b"POST /files/big.txt HTTP/1.1\r\nHost: x\r\n"
        b"Content-Length: 6291456\r\nConnection: close\r\n\r\n",
    )
    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 413 Payload Too Large"
    assert_security_headers(headers)
    assert_request_id(headers)
    assert headers["Content-Length"] == "0"
    assert headers["Connection"] == "close"
    assert set(headers) == {
        *SECURITY_HEADERS,
        "X-Request-ID",
        "Content-Length",
        "Connection",
    }
    assert body == b""


def test_payload_too_large_413_omits_cors(server_process) -> None:
    """The 413 response carries no CORS header even when an Origin is present."""

    raw = send_raw(
        server_process["host"],
        server_process["port"],
        b"POST /files/big.txt HTTP/1.1\r\nHost: x\r\n"
        b"Origin: http://example.com\r\n"
        b"Content-Length: 6291456\r\nConnection: close\r\n\r\n",
    )
    status_line, headers, _ = parse_response(raw)

    assert status_line == "HTTP/1.1 413 Payload Too Large"
    assert "Access-Control-Allow-Origin" not in headers
    assert set(headers) == {
        *SECURITY_HEADERS,
        "X-Request-ID",
        "Content-Length",
        "Connection",
    }


def _drain_to_first_429(host: str, port: int, request: bytes) -> bytes:
    """Send rapid keep-alive requests over one socket until a 429 is returned."""

    with socket.create_connection((host, port), timeout=5) as connection:
        connection.settimeout(5)
        for _ in range(8):
            connection.sendall(request)
            buffer = b""
            while b"\r\n\r\n" not in buffer:
                received = connection.recv(4096)
                if not received:
                    raise AssertionError("Connection closed before a 429 was observed")
                buffer += received
            header_block, remainder = buffer.split(b"\r\n\r\n", 1)
            content_length = 0
            for line in header_block.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    content_length = int(line.split(b":", 1)[1].strip())
            while len(remainder) < content_length:
                received = connection.recv(4096)
                if not received:
                    break
                remainder += received
            response = header_block + b"\r\n\r\n" + remainder[:content_length]
            if header_block.split(b"\r\n", 1)[0].startswith(b"HTTP/1.1 429"):
                return response
    raise AssertionError("No 429 response observed within the burst")


def test_rate_limited_429_bytes(limited_server_process) -> None:
    """The first 429 carries RateLimit headers and the exact denial body."""

    raw = _drain_to_first_429(
        limited_server_process["host"],
        limited_server_process["port"],
        b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 429 Too Many Requests"
    assert_security_headers(headers)
    assert_request_id(headers)
    assert headers["Retry-After"] == "1"
    assert headers["RateLimit-Limit"] == "2"
    assert headers["RateLimit-Remaining"] == "0"
    assert RATE_LIMIT_RESET_PATTERN.match(headers["RateLimit-Reset"])
    assert headers["Content-Length"] == "19"
    assert "Access-Control-Allow-Origin" not in headers
    assert set(headers) == {
        "Retry-After",
        "RateLimit-Limit",
        "RateLimit-Remaining",
        "RateLimit-Reset",
        *SECURITY_HEADERS,
        "X-Request-ID",
        "Content-Length",
    }
    assert body == b"Rate limit exceeded"


def test_rate_limited_429_omits_cors(limited_server_process) -> None:
    """A 429 with an Origin keeps RateLimit headers but emits no CORS header."""

    raw = _drain_to_first_429(
        limited_server_process["host"],
        limited_server_process["port"],
        b"GET /healthz HTTP/1.1\r\nHost: x\r\nOrigin: http://example.com\r\n\r\n",
    )
    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 429 Too Many Requests"
    assert headers["RateLimit-Limit"] == "2"
    assert headers["RateLimit-Remaining"] == "0"
    assert "Access-Control-Allow-Origin" not in headers
    assert body == b"Rate limit exceeded"


def test_connection_limited_503_bytes(limited_server_process) -> None:
    """A concurrent connection beyond the cap yields a 503 with its reason body."""

    host = limited_server_process["host"]
    port = limited_server_process["port"]

    holder = socket.create_connection((host, port), timeout=5)
    try:
        time.sleep(0.2)
        with socket.create_connection((host, port), timeout=5) as blocked:
            blocked.settimeout(5)
            buffer = b""
            while b"\r\n\r\n" not in buffer:
                received = blocked.recv(4096)
                if not received:
                    raise AssertionError("Connection closed before headers arrived")
                buffer += received
            header_block, remainder = buffer.split(b"\r\n\r\n", 1)
            content_length = 0
            for line in header_block.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    content_length = int(line.split(b":", 1)[1].strip())
            while len(remainder) < content_length:
                received = blocked.recv(4096)
                if not received:
                    break
                remainder += received
            raw = header_block + b"\r\n\r\n" + remainder[:content_length]
    finally:
        holder.close()

    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 503 Service Unavailable"
    assert_security_headers(headers)
    assert headers["Retry-After"] == "1"
    assert headers["Connection"] == "close"
    assert "X-Request-ID" not in headers
    assert "Access-Control-Allow-Origin" not in headers
    assert set(headers) == {
        "Retry-After",
        *SECURITY_HEADERS,
        "Content-Length",
        "Connection",
    }
    assert body == b"ip connection limit exceeded"
    assert headers["Content-Length"] == str(len(body))

"""Externally observable behavior of the HTTP server, pinned as a regression net."""

import pytest
import requests

from pyhttpd.domain import SECURITY_HEADERS
from tests.characterization.raw_client import send_raw, status_line

pytestmark = pytest.mark.integration


def _assert_security_headers(headers: requests.structures.CaseInsensitiveDict) -> None:
    """Assert the baseline security headers are present with their exact values."""

    for name, expected in SECURITY_HEADERS.items():
        if name == "Strict-Transport-Security":
            # HSTS is omitted over plaintext (RFC 6797 7.2); this server is HTTP.
            assert name not in headers
            continue
        assert headers.get(name) == expected


def test_echo_returns_message(base_url: str) -> None:
    """Echo returns the path segment as plain text with security headers."""

    response = requests.get(f"{base_url}/echo/hello-world", timeout=5)
    assert response.status_code == 200
    assert response.text == "hello-world"
    assert response.headers["Content-Type"] == "text/plain"
    _assert_security_headers(response.headers)


def test_echo_gzip_negotiated(base_url: str) -> None:
    """Echo gzip-encodes the payload when the client advertises gzip support."""

    response = requests.get(
        f"{base_url}/echo/compress-me",
        headers={"Accept-Encoding": "gzip"},
        timeout=5,
    )
    assert response.status_code == 200
    assert response.headers["Content-Encoding"] == "gzip"
    assert response.text == "compress-me"


def test_user_agent_echoed(base_url: str) -> None:
    """User-agent endpoint mirrors the request header back to the client."""

    response = requests.get(
        f"{base_url}/user-agent",
        headers={"User-Agent": "characterization/1.0"},
        timeout=5,
    )
    assert response.status_code == 200
    assert response.text == "characterization/1.0"


def test_healthz_ok(base_url: str) -> None:
    """Health check reports 200 during normal operation."""

    response = requests.get(f"{base_url}/healthz", timeout=5)
    assert response.status_code == 200


def test_request_id_present(base_url: str) -> None:
    """Responses carry an X-Request-ID correlation header."""

    response = requests.get(f"{base_url}/healthz", timeout=5)
    assert "X-Request-ID" in response.headers


def test_index_empty_directory_returns_200(base_url: str) -> None:
    """Index of an empty served directory responds with 200."""

    response = requests.get(f"{base_url}/", timeout=5)
    assert response.status_code == 200


def test_files_get_existing(server_process) -> None:
    """Existing files are served with their contents and security headers."""

    (server_process["directory"] / "note.txt").write_text("file-body", encoding="utf-8")
    response = requests.get(f"{server_process['base_url']}/files/note.txt", timeout=5)
    assert response.status_code == 200
    assert response.text == "file-body"
    _assert_security_headers(response.headers)


def test_files_post_creates(server_process) -> None:
    """POST to a file path persists the body and returns 201."""

    response = requests.post(
        f"{server_process['base_url']}/files/created.txt", data="persisted", timeout=5
    )
    assert response.status_code == 201
    assert (server_process["directory"] / "created.txt").read_text(
        encoding="utf-8"
    ) == "persisted"


def test_unknown_route_404(base_url: str) -> None:
    """Unknown routes respond with 404."""

    assert requests.get(f"{base_url}/does-not-exist", timeout=5).status_code == 404


def test_method_not_allowed_405(base_url: str) -> None:
    """Disallowed methods on a known route respond with 405."""

    assert requests.delete(f"{base_url}/echo/x", timeout=5).status_code == 405


def test_traversal_via_files_forbidden(server_process) -> None:
    """Path traversal through /files is rejected with 403."""

    raw = send_raw(
        server_process["host"],
        server_process["port"],
        b"GET /files/../secret HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    assert status_line(raw).startswith("HTTP/1.1 403")


def test_malformed_request_line_400(server_process) -> None:
    """A malformed request line is rejected with 400."""

    raw = send_raw(
        server_process["host"],
        server_process["port"],
        b"GET\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    assert status_line(raw).startswith("HTTP/1.1 400")


def test_oversized_body_413(server_process) -> None:
    """A request declaring a body beyond the size limit is rejected with 413."""

    declared_length = 6 * 1024 * 1024
    request = (
        b"POST /files/big.txt HTTP/1.1\r\nHost: x\r\n"
        b"Content-Length: " + str(declared_length).encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )
    raw = send_raw(server_process["host"], server_process["port"], request)
    assert status_line(raw).startswith("HTTP/1.1 413")


def test_rate_limit_429(limited_server_process) -> None:
    """Bursts beyond the configured rate limit yield 429 for some requests."""

    base = limited_server_process["base_url"]
    statuses = [
        requests.get(f"{base}/healthz", timeout=5).status_code for _ in range(8)
    ]
    assert 429 in statuses

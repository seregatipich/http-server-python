"""Integration tests exercising the public HTTP endpoints."""

from __future__ import annotations

import gzip
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import requests

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo


def test_root_endpoint_returns_empty_body(base_url: str) -> None:
    """Root should respond with an empty payload."""

    response = requests.get(f"{base_url}/", timeout=5)
    assert response.status_code == 200
    assert response.content == b""


def test_echo_endpoint_round_trips_payload(base_url: str) -> None:
    """Echo path should round-trip the payload unmodified."""

    response = requests.get(f"{base_url}/echo/sample", timeout=5)
    assert response.status_code == 200
    assert response.text == "sample"


def test_user_agent_endpoint_reflects_header(base_url: str) -> None:
    """User-agent endpoint must mirror the request header."""

    headers = {"User-Agent": "pytest-agent"}
    response = requests.get(f"{base_url}/user-agent", headers=headers, timeout=5)
    assert response.status_code == 200
    assert response.text == "pytest-agent"


def test_echo_responds_with_gzip_when_requested(base_url: str) -> None:
    """Echo should gzip payloads when the client opts in."""

    headers = {"Accept-Encoding": "gzip"}
    with requests.get(
        f"{base_url}/echo/zip",
        headers=headers,
        timeout=5,
        stream=True,
    ) as response:
        assert response.status_code == 200
        assert response.headers.get("Content-Encoding") == "gzip"
        response.raw.decode_content = False
        payload = response.raw.read()
    assert gzip.decompress(payload) == b"zip"


def test_file_round_trip_uses_chunked_transfer(
    base_url: str, server_process: "ServerProcessInfo"
) -> None:
    """Uploading a file then reading it back should use chunked transfer."""

    filename = "payload.txt"
    payload = b"file-body"
    post_response = requests.post(
        f"{base_url}/files/{filename}",
        data=payload,
        timeout=5,
    )
    assert post_response.status_code == 201

    get_response = requests.get(f"{base_url}/files/{filename}", timeout=5)
    assert get_response.status_code == 200
    assert get_response.content == payload
    assert get_response.headers.get("Transfer-Encoding") == "chunked"

    stored_path = Path(server_process["directory"]) / filename
    assert stored_path.read_bytes() == payload


def test_healthz_endpoint_returns_200_when_healthy(base_url: str) -> None:
    """Health check endpoint should return 200 OK during normal operation."""

    response = requests.get(f"{base_url}/healthz", timeout=5)
    assert response.status_code == 200
    assert response.content == b""
    assert "strict-transport-security" in response.headers


def test_cors_simple_request_with_origin(base_url: str) -> None:
    """Simple CORS request should include Access-Control-Allow-Origin header."""

    headers = {"Origin": "https://example.com"}
    response = requests.get(f"{base_url}/", headers=headers, timeout=5)
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "*"
    assert response.headers.get("Access-Control-Expose-Headers") == "X-Request-ID"


def test_cors_echo_endpoint_with_origin(base_url: str) -> None:
    """Echo endpoint should include CORS headers when Origin is present."""

    headers = {"Origin": "https://app.example.com"}
    response = requests.get(f"{base_url}/echo/test", headers=headers, timeout=5)
    assert response.status_code == 200
    assert response.text == "test"
    assert response.headers.get("Access-Control-Allow-Origin") == "*"


def test_cors_preflight_options_request(base_url: str) -> None:
    """OPTIONS preflight request should return 204 with CORS headers."""

    headers = {
        "Origin": "https://example.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type",
    }
    response = requests.options(f"{base_url}/files/data", headers=headers, timeout=5)
    assert response.status_code == 204
    assert response.content == b""
    assert response.headers.get("Access-Control-Allow-Origin") == "*"
    assert "GET" in response.headers.get("Access-Control-Allow-Methods", "")
    assert "POST" in response.headers.get("Access-Control-Allow-Methods", "")
    assert "OPTIONS" in response.headers.get("Access-Control-Allow-Methods", "")
    assert "Content-Type" in response.headers.get("Access-Control-Allow-Headers", "")
    assert response.headers.get("Access-Control-Max-Age") == "86400"


def test_cors_file_post_with_origin(base_url: str) -> None:
    """File POST with Origin should include CORS headers in response."""

    headers = {"Origin": "https://example.com"}
    payload = b"cors-test-data"
    response = requests.post(
        f"{base_url}/files/cors-test.txt",
        data=payload,
        headers=headers,
        timeout=5,
    )
    assert response.status_code == 201
    assert response.headers.get("Access-Control-Allow-Origin") == "*"


def test_cors_file_get_with_origin(
    base_url: str, server_process: "ServerProcessInfo"
) -> None:
    """File GET with Origin should include CORS headers in streaming response."""

    filename = "cors-get-test.txt"
    payload = b"cors-get-data"
    file_path = Path(server_process["directory"]) / filename
    file_path.write_bytes(payload)

    headers = {"Origin": "https://example.com"}
    response = requests.get(f"{base_url}/files/{filename}", headers=headers, timeout=5)
    assert response.status_code == 200
    assert response.content == payload
    assert response.headers.get("Access-Control-Allow-Origin") == "*"
    assert response.headers.get("Transfer-Encoding") == "chunked"


def test_cors_not_found_with_origin(base_url: str) -> None:
    """404 responses should include CORS headers when Origin is present."""

    headers = {"Origin": "https://example.com"}
    response = requests.get(f"{base_url}/nonexistent", headers=headers, timeout=5)
    assert response.status_code == 404
    assert response.headers.get("Access-Control-Allow-Origin") == "*"


def test_cors_without_origin_header(base_url: str) -> None:
    """Requests without Origin header should not include CORS headers."""

    response = requests.get(f"{base_url}/", timeout=5)
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers

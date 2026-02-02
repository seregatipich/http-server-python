"""Integration tests for request correlation ID end-to-end flow."""

from __future__ import annotations

import re
import socket
import threading
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import requests

from server.bootstrap.config import MAX_BODY_BYTES

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo


def test_server_generates_correlation_id_when_not_provided(base_url: str) -> None:
    """Server should generate UUID correlation IDs by default."""
    response = requests.get(f"{base_url}/", timeout=5)
    assert response.status_code == 200
    assert "X-Request-ID" in response.headers
    correlation_id = response.headers["X-Request-ID"]
    assert correlation_id is not None
    assert len(correlation_id) == 36
    uuid_pattern = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    assert uuid_pattern.match(correlation_id)


def test_server_accepts_incoming_correlation_id(base_url: str) -> None:
    """Server should echo back provided correlation IDs."""
    custom_correlation_id = "custom-request-id-12345"
    response = requests.get(
        f"{base_url}/", headers={"X-Request-ID": custom_correlation_id}, timeout=5
    )
    assert response.status_code == 200
    assert "X-Request-ID" in response.headers
    assert response.headers["X-Request-ID"] == custom_correlation_id


def test_correlation_id_preserved_across_request_types(base_url: str) -> None:
    """Correlation IDs must persist across endpoints."""
    custom_correlation_id = "test-correlation-xyz"

    response1 = requests.get(
        f"{base_url}/echo/test",
        headers={"X-Request-ID": custom_correlation_id},
        timeout=5,
    )
    assert response1.status_code == 200
    assert response1.headers["X-Request-ID"] == custom_correlation_id
    response2 = requests.get(
        f"{base_url}/user-agent",
        headers={"X-Request-ID": custom_correlation_id, "User-Agent": "test"},
        timeout=5,
    )
    assert response2.status_code == 200
    assert response2.headers["X-Request-ID"] == custom_correlation_id


def test_correlation_id_with_file_operations(
    base_url: str, server_process: ServerProcessInfo
) -> None:
    """File endpoints should honor correlation IDs end-to-end."""
    custom_correlation_id = "file-op-correlation-id"

    post_response = requests.post(
        f"{base_url}/files/test.txt",
        data=b"test content",
        headers={"X-Request-ID": custom_correlation_id},
        timeout=5,
    )
    assert post_response.status_code == 201
    assert post_response.headers["X-Request-ID"] == custom_correlation_id

    get_response = requests.get(
        f"{base_url}/files/test.txt",
        headers={"X-Request-ID": custom_correlation_id},
        timeout=5,
    )
    assert get_response.status_code == 200
    assert get_response.headers["X-Request-ID"] == custom_correlation_id

    log_file = Path(server_process["log_file"])
    log_content = log_file.read_text(encoding="utf-8")
    assert "Stored file" in log_content
    assert "Served file" in log_content
    file_op_logs = [
        line
        for line in log_content.split("\n")
        if custom_correlation_id in line
        and ("Stored file" in line or "Served file" in line)
    ]
    assert len(file_op_logs) >= 2


def test_different_requests_have_different_correlation_ids(base_url: str) -> None:
    """Separate requests must receive unique IDs."""
    response1 = requests.get(f"{base_url}/", timeout=5)
    correlation_id1 = response1.headers.get("X-Request-ID")

    response2 = requests.get(f"{base_url}/", timeout=5)
    correlation_id2 = response2.headers.get("X-Request-ID")

    assert correlation_id1 is not None
    assert correlation_id2 is not None
    assert correlation_id1 != correlation_id2


def test_correlation_id_isolated_across_concurrent_requests(base_url: str) -> None:
    """Concurrent requests keep their provided IDs."""
    results = {}

    def make_request(request_id: str):
        custom_correlation_id = f"concurrent-{request_id}"
        response = requests.get(
            f"{base_url}/echo/test",
            headers={"X-Request-ID": custom_correlation_id},
            timeout=5,
        )
        results[request_id] = response.headers.get("X-Request-ID")

    threads = [threading.Thread(target=make_request, args=(str(i),)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for request_id, correlation_id in results.items():
        expected = f"concurrent-{request_id}"
        assert correlation_id == expected, f"Expected {expected}, got {correlation_id}"


def test_correlation_id_with_error_responses(base_url: str) -> None:
    """Error responses should still echo correlation IDs."""
    custom_correlation_id = "error-test-correlation"

    response = requests.get(
        f"{base_url}/nonexistent",
        headers={"X-Request-ID": custom_correlation_id},
        timeout=5,
    )
    assert response.status_code == 404
    assert response.headers["X-Request-ID"] == custom_correlation_id


def test_payload_too_large_response_includes_correlation_id(
    server_process,
) -> None:
    """Oversized payload rejections must still include correlation IDs."""

    host = server_process["host"]
    port = server_process["port"]
    request = (
        "POST /files/oversized.txt HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Length: {MAX_BODY_BYTES + 1}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )

    with socket.create_connection((host, port), timeout=5) as client:
        client.sendall(request.encode("ascii"))
        response_bytes = b""
        while b"\r\n\r\n" not in response_bytes:
            chunk = client.recv(4096)
            if not chunk:
                break
            response_bytes += chunk

    header_block = response_bytes.split(b"\r\n\r\n", 1)[0].decode()
    header_lines = header_block.split("\r\n")
    status_line = header_lines[0]
    parsed_headers = {}
    for line in header_lines[1:]:
        if ": " in line:
            name, value = line.split(": ", 1)
            parsed_headers[name.lower()] = value

    assert status_line.startswith("HTTP/1.1 413"), status_line
    correlation_id = parsed_headers.get("x-request-id")
    assert correlation_id is not None
    assert correlation_id != ""

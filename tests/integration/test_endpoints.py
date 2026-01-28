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

"""End-to-end HTTP/2 tests driving the server with curl --http2 (F13)."""

from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest
import requests

pytestmark = pytest.mark.integration

if shutil.which("curl") is None:
    pytest.skip("curl not available", allow_module_level=True)

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo


def _curl_h2(*args: str) -> str:
    result = subprocess.run(
        ["curl", "-s", "--http2-prior-knowledge", *args],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    return result.stdout


def test_http2_get_echo(http2_server: "ServerProcessInfo") -> None:
    output = _curl_h2("-D", "-", f"{http2_server['base_url']}/echo/h2-hello")
    assert "HTTP/2 200" in output
    assert output.strip().endswith("h2-hello")


def test_http2_serves_security_headers(http2_server: "ServerProcessInfo") -> None:
    output = _curl_h2("-D", "-", f"{http2_server['base_url']}/echo/x")
    assert "content-security-policy: default-src 'self'" in output.lower()


def test_http2_post_then_get_file(http2_server: "ServerProcessInfo") -> None:
    base_url = http2_server["base_url"]
    _curl_h2("-X", "POST", "--data-binary", "h2-body", f"{base_url}/files/h2.txt")
    body = _curl_h2(f"{base_url}/files/h2.txt")
    assert body == "h2-body"


def test_http1_still_works_when_http2_enabled(
    http2_server: "ServerProcessInfo",
) -> None:
    # A plain HTTP/1.1 client must still be served (h2c sniff falls through).
    response = requests.get(f"{http2_server['base_url']}/echo/plain", timeout=5)
    assert response.status_code == 200
    assert response.text == "plain"

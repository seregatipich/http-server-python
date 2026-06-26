"""Integration tests for Phase 4 hardening features."""

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Generator

import pytest
import requests

from tests.conftest import PROJECT_ROOT, _launch_server  # type: ignore[attr-defined]
from tests.utils.http import read_http_response, reserve_port

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from _pytest.tmpdir import TempPathFactory

    from tests.conftest import ServerProcessInfo


@pytest.fixture(name="slow_server_process")
def _slow_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator["ServerProcessInfo", None, None]:
    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-slow")
    log_file = directory / "server.log"
    yield from _launch_server(
        host, port, directory, ["--header-read-timeout", "1"], log_file=log_file
    )


@pytest.fixture(name="sniff_server_process")
def _sniff_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator["ServerProcessInfo", None, None]:
    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-sniff")
    log_file = directory / "server.log"
    yield from _launch_server(
        host, port, directory, ["--content-sniffing"], log_file=log_file
    )


def test_slow_header_sender_gets_408(slow_server_process: "ServerProcessInfo") -> None:
    """A client that starts a request then stalls is cut off with a 408."""
    host = slow_server_process["host"]
    port = slow_server_process["port"]
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(b"GET / HTTP/1.1\r\n")  # partial request, then stall
        response = read_http_response(sock)
    assert response.status_line.startswith("HTTP/1.1 408")


def test_content_sniffing_detects_png_without_extension(
    sniff_server_process: "ServerProcessInfo",
) -> None:
    """An extension-less PNG is served with image/png when sniffing is on."""
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    (Path(sniff_server_process["directory"]) / "blob").write_bytes(png_bytes)
    base_url = sniff_server_process["base_url"]
    response = requests.get(f"{base_url}/files/blob", timeout=5)
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "image/png"


def test_invalid_configuration_aborts_startup(tmp_path: Path) -> None:
    """A bad TLS pair makes the server exit non-zero with a clear message."""
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyhttpd",
            "--directory",
            str(tmp_path),
            "--port",
            "0",
            "--cert",
            "/nonexistent/cert.pem",
            "--key",
            "/nonexistent/key.pem",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert process.returncode != 0
    assert "Invalid configuration" in (process.stderr + process.stdout)


def test_transfer_encoding_request_rejected(
    server_process: "ServerProcessInfo",
) -> None:
    """A Transfer-Encoding request is rejected with 400 to prevent framing desync."""
    host = server_process["host"]
    port = server_process["port"]
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(
            b"POST /files/x HTTP/1.1\r\n"
            b"Host: x\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            b"0\r\n\r\n"
        )
        response = read_http_response(sock)
    assert response.status_line.startswith("HTTP/1.1 400")


def test_conflicting_content_length_rejected(
    server_process: "ServerProcessInfo",
) -> None:
    """Two differing Content-Length headers are rejected with 400."""
    host = server_process["host"]
    port = server_process["port"]
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(
            b"POST /files/x HTTP/1.1\r\n"
            b"Host: x\r\n"
            b"Content-Length: 5\r\n"
            b"Content-Length: 6\r\n"
            b"Connection: close\r\n\r\n"
            b"hello!"
        )
        response = read_http_response(sock)
    assert response.status_line.startswith("HTTP/1.1 400")

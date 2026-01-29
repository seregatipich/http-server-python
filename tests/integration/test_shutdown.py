"""Integration tests for graceful shutdown behavior."""

# pylint: disable=redefined-outer-name

import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from tests.utils.http import (read_http_response, reserve_port,
                              send_signal_to_process, wait_for_healthz_status,
                              wait_for_port)


@pytest.fixture
def server_process_info():
    """Start a server process and yield its details."""
    port = reserve_port()
    temp_dir = tempfile.mkdtemp()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "main",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--directory",
            temp_dir,
            "--shutdown-grace-seconds",
            "5",
            "--socket-timeout",
            "30",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=Path(__file__).parent.parent.parent,
    )
    wait_for_port("127.0.0.1", port, timeout=5.0)
    yield {"process": process, "port": port, "host": "127.0.0.1", "temp_dir": temp_dir}
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=2.0)


def test_healthz_returns_200_during_normal_operation(server_process_info):
    """Test /healthz returns 200 OK when server is healthy."""
    host = server_process_info["host"]
    port = server_process_info["port"]
    with socket.create_connection((host, port), timeout=2.0) as sock:
        request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sock.sendall(request)
        response = read_http_response(sock)
        assert response.status_line == "HTTP/1.1 200 OK"
        assert response.body == b""
        assert "strict-transport-security" in response.headers


def test_healthz_returns_503_during_draining(server_process_info):
    """Test /healthz returns 503 after receiving shutdown signal."""
    host = server_process_info["host"]
    port = server_process_info["port"]
    process = server_process_info["process"]
    assert wait_for_healthz_status(host, port, 200, timeout=2.0)
    send_signal_to_process(process.pid, signal.SIGTERM)
    time.sleep(0.2)
    assert wait_for_healthz_status(host, port, 503, timeout=2.0)
    with socket.create_connection((host, port), timeout=2.0) as sock:
        request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sock.sendall(request)
        response = read_http_response(sock)
        assert response.status_line == "HTTP/1.1 503 Service Unavailable"
        assert response.body == b"draining"
        assert response.headers.get("connection") == "close"


def test_server_drains_before_exit(server_process_info):
    """Test server waits for in-flight requests before exiting."""
    host = server_process_info["host"]
    port = server_process_info["port"]
    process = server_process_info["process"]
    temp_dir = server_process_info["temp_dir"]
    test_file = Path(temp_dir) / "test.txt"
    test_file.write_bytes(b"x" * 1000)
    sock = socket.create_connection((host, port), timeout=2.0)
    try:
        request = b"GET /files/test.txt HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sock.sendall(request)
        time.sleep(0.1)
        send_signal_to_process(process.pid, signal.SIGTERM)
        time.sleep(0.2)
        assert process.poll() is None
        response = read_http_response(sock)
        assert response.status_line == "HTTP/1.1 200 OK"
        assert len(response.body) == 1000
    finally:
        sock.close()
    process.wait(timeout=6.0)
    assert process.returncode == 0


def test_new_connections_rejected_during_draining(server_process_info):
    """Test new connections receive 503 immediately when draining."""
    host = server_process_info["host"]
    port = server_process_info["port"]
    process = server_process_info["process"]
    assert wait_for_healthz_status(host, port, 200, timeout=2.0)
    send_signal_to_process(process.pid, signal.SIGTERM)
    time.sleep(0.3)
    with socket.create_connection((host, port), timeout=2.0) as sock:
        request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sock.sendall(request)
        response = read_http_response(sock)
        assert response.status_line == "HTTP/1.1 503 Service Unavailable"
        assert response.body == b"draining"


def test_sigint_triggers_graceful_shutdown(server_process_info):
    """Test SIGINT also triggers graceful shutdown."""
    host = server_process_info["host"]
    port = server_process_info["port"]
    process = server_process_info["process"]
    assert wait_for_healthz_status(host, port, 200, timeout=2.0)
    send_signal_to_process(process.pid, signal.SIGINT)
    time.sleep(0.2)
    assert wait_for_healthz_status(host, port, 503, timeout=2.0)
    process.wait(timeout=6.0)
    assert process.returncode == 0


def test_shutdown_completes_within_grace_period(server_process_info):
    """Test server shuts down within configured grace period."""
    host = server_process_info["host"]
    port = server_process_info["port"]
    process = server_process_info["process"]
    assert wait_for_healthz_status(host, port, 200, timeout=2.0)
    start = time.monotonic()
    send_signal_to_process(process.pid, signal.SIGTERM)
    process.wait(timeout=7.0)
    elapsed = time.monotonic() - start
    assert elapsed < 6.0
    assert process.returncode == 0


def test_multiple_healthz_requests_during_draining(server_process_info):
    """Test multiple /healthz requests all return 503 during draining."""
    host = server_process_info["host"]
    port = server_process_info["port"]
    process = server_process_info["process"]
    send_signal_to_process(process.pid, signal.SIGTERM)
    time.sleep(0.2)
    for _ in range(3):
        with socket.create_connection((host, port), timeout=2.0) as sock:
            request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"
            sock.sendall(request)
            response = read_http_response(sock)
            assert response.status_line == "HTTP/1.1 503 Service Unavailable"

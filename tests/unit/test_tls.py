"""Unit tests for TLS socket/context wiring (handshake off the accept thread)."""

import socket
import ssl
import threading
from unittest.mock import patch

import pytest

from pyhttpd.adapters.config import parse_cli_args
from pyhttpd.adapters.tls import (
    _sni_contexts,
    build_tls_context,
    create_server_socket,
    establish_tls,
)
from tests.utils.certs import generate_ca, openssl_available

if not openssl_available():
    pytest.skip("openssl not available", allow_module_level=True)


@pytest.fixture(name="tls_cert", scope="module")
def _tls_cert(tmp_path_factory):
    """Generate a self-signed cert/key pair usable by the server context."""
    certs = tmp_path_factory.mktemp("unit-tls-certs")
    cert, key = generate_ca(certs)
    return str(cert), str(key)


def _tls_args(cert, key, extra=None):
    argv = ["--host", "127.0.0.1", "--port", "0", "--cert", cert, "--key", key]
    if extra:
        argv.extend(extra)
    return parse_cli_args(argv)


def test_sni_contexts_keys_are_lowercased(tls_cert):
    cert, key = tls_cert
    contexts = _sni_contexts(
        _tls_args(cert, key, ["--tls-sni", f"Example.COM:{cert}:{key}"])
    )
    assert "example.com" in contexts


def test_build_tls_context_exits_on_malformed_sni(tls_cert):
    cert, key = tls_cert
    with patch("pyhttpd.adapters.tls.sys.exit") as mock_exit:
        build_tls_context(_tls_args(cert, key, ["--tls-sni", "this-is-not-valid"]))
    mock_exit.assert_called_with(1)


def test_listener_is_plain_even_with_tls_enabled(tls_cert):
    """The listening socket must not be TLS-wrapped, so accept() never handshakes."""
    cert, key = tls_cert
    sock = create_server_socket(_tls_args(cert, key))
    try:
        assert not isinstance(sock, ssl.SSLSocket)
    finally:
        sock.close()


def test_build_tls_context_is_none_without_cert():
    """No certificate means no TLS context (plaintext server)."""
    assert (
        build_tls_context(parse_cli_args(["--host", "127.0.0.1", "--port", "0"]))
        is None
    )


def test_build_tls_context_present_with_cert(tls_cert):
    """A certificate produces a usable server SSL context."""
    cert, key = tls_cert
    assert isinstance(build_tls_context(_tls_args(cert, key)), ssl.SSLContext)


def test_establish_tls_completes_handshake_on_a_connected_socket(tls_cert):
    """establish_tls wraps an accepted socket and finishes the handshake in-thread."""
    cert, key = tls_cert
    context = build_tls_context(_tls_args(cert, key))
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    received: dict[str, bytes] = {}

    def serve():
        conn, _ = listener.accept()
        tls_conn = establish_tls(conn, context, 5.0)
        received["payload"] = tls_conn.recv(16)
        tls_conn.sendall(b"pong")
        tls_conn.close()

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        client_context = ssl.create_default_context()
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        client = client_context.wrap_socket(raw, server_hostname="localhost")
        client.sendall(b"ping")
        assert client.recv(16) == b"pong"
        client.close()
    finally:
        worker.join(timeout=5)
        listener.close()

    assert received["payload"] == b"ping"

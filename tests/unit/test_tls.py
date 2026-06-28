"""Unit tests for TLS socket/context wiring (handshake off the accept thread)."""

import os
import socket
import ssl
import threading

from pyhttpd.adapters.config import parse_cli_args
from pyhttpd.adapters.tls import build_tls_context, create_server_socket, establish_tls

CERT = os.path.abspath("certs/cert.pem")
KEY = os.path.abspath("certs/key.pem")


def _tls_args():
    return parse_cli_args(
        ["--host", "127.0.0.1", "--port", "0", "--cert", CERT, "--key", KEY]
    )


def test_listener_is_plain_even_with_tls_enabled():
    """The listening socket must not be TLS-wrapped, so accept() never handshakes."""
    sock = create_server_socket(_tls_args())
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


def test_build_tls_context_present_with_cert():
    """A certificate produces a usable server SSL context."""
    assert isinstance(build_tls_context(_tls_args()), ssl.SSLContext)


def test_establish_tls_completes_handshake_on_a_connected_socket():
    """establish_tls wraps an accepted socket and finishes the handshake in-thread."""
    context = build_tls_context(_tls_args())
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

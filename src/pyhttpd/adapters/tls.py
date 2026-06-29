"""Socket creation and TLS configuration (SNI multi-cert and mutual TLS)."""

import argparse
import logging
import socket
import ssl
import sys
from typing import Dict

SOCKET_LOGGER = logging.getLogger("http_server.socket")


def create_server_socket(args: argparse.Namespace) -> socket.socket:
    """Create the plain listening socket.

    The listener is never TLS-wrapped: wrapping it makes accept() run the full
    TLS handshake synchronously on the single accept thread, so one silent peer
    blocks every other client (a pre-auth listener DoS). TLS is instead applied
    per connection inside the worker thread via ``establish_tls``.
    """
    server_socket = socket.create_server((args.host, args.port), reuse_port=True)
    server_socket.settimeout(0.5)
    return server_socket


def build_tls_context(args: argparse.Namespace) -> ssl.SSLContext | None:
    """Build the server SSL context, or None when TLS is not configured."""
    if not (args.cert and args.key):
        return None
    try:
        return _build_tls_context(args)
    except (ssl.SSLError, OSError) as error:
        SOCKET_LOGGER.critical(
            "Failed to load TLS certificates", extra={"error": str(error)}
        )
        sys.exit(1)


def establish_tls(
    plain_socket: socket.socket,
    context: ssl.SSLContext,
    handshake_timeout: float | None,
) -> ssl.SSLSocket:
    """Wrap an accepted socket and complete the TLS handshake in the worker.

    The handshake is bounded by ``handshake_timeout`` so a slow or silent peer
    cannot pin the worker indefinitely; it runs here (not on the accept thread)
    so the listener keeps accepting other connections.
    """
    tls_socket = context.wrap_socket(
        plain_socket, server_side=True, do_handshake_on_connect=False
    )
    tls_socket.settimeout(handshake_timeout)
    tls_socket.do_handshake()
    return tls_socket


def _build_tls_context(args: argparse.Namespace) -> ssl.SSLContext:
    default_context = _server_context(args.cert, args.key, args)
    sni_contexts = _sni_contexts(args)
    if sni_contexts:

        def _select(
            sslsocket: ssl.SSLSocket, servername: str, _context: ssl.SSLContext
        ) -> None:
            chosen = sni_contexts.get(servername)
            if chosen is not None:
                sslsocket.context = chosen

        default_context.sni_callback = _select  # type: ignore[assignment]
    return default_context


def _server_context(cert: str, key: str, args: argparse.Namespace) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    if getattr(args, "enable_http2", False):
        context.set_alpn_protocols(["h2", "http/1.1"])
    client_ca = getattr(args, "tls_client_ca", None)
    if client_ca:
        context.load_verify_locations(client_ca)
        context.verify_mode = (
            ssl.CERT_REQUIRED
            if getattr(args, "tls_require_client_cert", False)
            else ssl.CERT_OPTIONAL
        )
    return context


def _sni_contexts(args: argparse.Namespace) -> Dict[str, ssl.SSLContext]:
    contexts: Dict[str, ssl.SSLContext] = {}
    for spec in getattr(args, "tls_sni", None) or []:
        host, cert, key = _parse_sni_spec(spec)
        contexts[host] = _server_context(cert, key, args)
    return contexts


def _parse_sni_spec(spec: str) -> tuple[str, str, str]:
    parts = spec.split(":", 2)
    if len(parts) != 3 or not all(parts):
        raise ValueError(f"invalid --tls-sni spec: {spec!r} (host:cert:key)")
    return parts[0], parts[1], parts[2]

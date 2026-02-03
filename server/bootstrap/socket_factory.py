"""Socket creation and TLS configuration."""

import argparse
import logging
import socket
import ssl
import sys

from server.domain.correlation_id import CorrelationLoggerAdapter

SOCKET_LOGGER = CorrelationLoggerAdapter(logging.getLogger("http_server.socket"), {})


def create_server_socket(args: argparse.Namespace) -> socket.socket:
    """Create and configure the server socket, optionally wrapping in TLS."""
    server_socket = socket.create_server((args.host, args.port), reuse_port=True)
    server_socket.settimeout(0.5)
    if args.cert and args.key:
        try:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(args.cert, args.key)
            server_socket = tls_context.wrap_socket(server_socket, server_side=True)
        except ssl.SSLError as error:
            SOCKET_LOGGER.critical(
                "Failed to load TLS certificates",
                extra={"error": str(error)},
            )
            sys.exit(1)
    return server_socket

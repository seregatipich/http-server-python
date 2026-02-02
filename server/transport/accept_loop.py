"""Main connection acceptance loop."""

import argparse
import logging
import socket
import threading
from typing import Optional

from server.bootstrap.config import SECURITY_HEADERS, ServerConfig
from server.bootstrap.socket_factory import create_server_socket
from server.domain.correlation_id import CorrelationLoggerAdapter
from server.domain.response_builders import (
    connection_limited_response,
    draining_response,
)
from server.domain.token_bucket import TokenBucketLimiter, TokenBucketSettings
from server.lifecycle.state import ServerLifecycle
from server.pipeline.io import send_response
from server.security.cors import CorsConfig
from server.transport.connection_limiter import ConnectionLimiter
from server.transport.context import WorkerContext
from server.transport.worker import handle_client

ACCEPT_LOGGER = CorrelationLoggerAdapter(logging.getLogger("http_server.accept"), {})


def run_server(
    args: argparse.Namespace, config: ServerConfig, lifecycle: ServerLifecycle
) -> None:
    """Create listening socket and handle client lifecycle."""

    server_socket = create_server_socket(args)

    connection_limiter = ConnectionLimiter(
        args.max_connections,
        args.max_connections_per_ip,
    )
    rate_limiter: Optional[TokenBucketLimiter] = None
    if args.rate_limit > 0 and args.rate_window_ms > 0:
        rate_limiter = TokenBucketLimiter(
            TokenBucketSettings(
                rate_limit=args.rate_limit,
                window_ms=args.rate_window_ms,
                burst_capacity=args.burst_capacity,
                dry_run=args.rate_limit_dry_run,
            )
        )

    cors_config = CorsConfig(
        allowed_origins=[
            o.strip() for o in args.cors_allowed_origins.split(",") if o.strip()
        ],
        allowed_methods=[
            m.strip() for m in args.cors_allowed_methods.split(",") if m.strip()
        ],
        allowed_headers=[
            h.strip() for h in args.cors_allowed_headers.split(",") if h.strip()
        ],
        expose_headers=[
            h.strip() for h in args.cors_expose_headers.split(",") if h.strip()
        ],
        allow_credentials=args.cors_allow_credentials,
        max_age=args.cors_max_age,
    )

    handler_context = WorkerContext(
        directory=args.directory,
        connection_limiter=connection_limiter,
        rate_limiter=rate_limiter,
        lifecycle=lifecycle,
        config=config,
        cors_config=cors_config,
    )

    try:
        while True:
            try:
                client_socket, client_address = server_socket.accept()
            except socket.timeout:
                if lifecycle.should_stop():
                    break
                continue
            except OSError as error:
                if lifecycle.should_stop():
                    break
                ACCEPT_LOGGER.error("Socket accept failed", extra={"error": str(error)})
                continue

            if lifecycle.is_draining():
                send_response(client_socket, draining_response(SECURITY_HEADERS))
                client_socket.close()
                continue

            ACCEPT_LOGGER.debug("Accepted client", extra={"client": client_address})
            allowed, limit_type = connection_limiter.acquire(client_address[0])
            if not allowed:
                send_response(
                    client_socket,
                    connection_limited_response(limit_type, SECURITY_HEADERS),
                )
                client_socket.close()
                continue
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address, handler_context),
                daemon=False,
            )
            thread.start()
    finally:
        server_socket.close()
        ACCEPT_LOGGER.info("Waiting for active connections to complete")
        lifecycle.wait_for_workers(config.shutdown_grace_seconds)
        ACCEPT_LOGGER.info("Server shutdown complete")

"""Main connection acceptance loop."""

import argparse
import logging
import socket
import threading
from typing import Optional

from pyhttpd.bootstrap import ServerConfig, create_server_socket
from pyhttpd.domain import (
    SECURITY_HEADERS,
    CorsConfig,
    LifecycleState,
    TokenBucketLimiter,
    TokenBucketSettings,
    connection_limited_response,
    draining_response,
    format_client_address,
)
from pyhttpd.pipeline import send_response
from pyhttpd.transport.connection_limiter import ConnectionLimiter
from pyhttpd.transport.context import WorkerContext
from pyhttpd.transport.worker import handle_client

ACCEPT_LOGGER = logging.getLogger("http_server.transport.accept")


def _create_cors_config(args: argparse.Namespace) -> CorsConfig:
    """Create CORS configuration from CLI arguments."""
    return CorsConfig(
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


def _create_rate_limiter(args: argparse.Namespace) -> Optional[TokenBucketLimiter]:
    """Create rate limiter if configured."""
    if args.rate_limit > 0 and args.rate_window_ms > 0:
        return TokenBucketLimiter(
            TokenBucketSettings(
                rate_limit=args.rate_limit,
                window_ms=args.rate_window_ms,
                burst_capacity=args.burst_capacity,
                dry_run=args.rate_limit_dry_run,
            )
        )
    return None


def _handle_accepted_client(
    client_socket: socket.socket,
    client_address: tuple[str, int],
    connection_limiter: ConnectionLimiter,
    handler_context: WorkerContext,
) -> None:
    """Handle a newly accepted client connection."""
    client_addr_str = format_client_address(client_address)
    if ACCEPT_LOGGER.isEnabledFor(logging.DEBUG):
        ACCEPT_LOGGER.debug(
            "Client connection accepted",
            extra={"event": "client_accepted", "client": client_addr_str},
        )

    allowed, limit_type = connection_limiter.acquire(client_address[0])
    if not allowed:
        limit_event = (
            "connection_limit_reached"
            if limit_type == "global"
            else "per_ip_limit_reached"
        )
        ACCEPT_LOGGER.warning(
            "Connection limit reached",
            extra={
                "event": limit_event,
                "client": client_addr_str,
                "limit_type": limit_type,
            },
        )
        send_response(
            client_socket,
            connection_limited_response(limit_type, SECURITY_HEADERS),
        )
        client_socket.close()
        return

    thread = threading.Thread(
        target=handle_client,
        args=(client_socket, client_address, handler_context),
        daemon=False,
    )
    thread.start()


def _create_worker_context(
    args: argparse.Namespace,
    config: ServerConfig,
    lifecycle: LifecycleState,
    connection_limiter: ConnectionLimiter,
) -> WorkerContext:
    return WorkerContext(
        directory=args.directory,
        connection_limiter=connection_limiter,
        rate_limiter=_create_rate_limiter(args),
        lifecycle=lifecycle,
        config=config,
        cors_config=_create_cors_config(args),
    )


def _accept_client(server_socket: socket.socket, lifecycle: LifecycleState):
    try:
        return server_socket.accept()
    except socket.timeout:
        return None if lifecycle.should_stop() else False
    except OSError as error:
        if lifecycle.should_stop():
            return None
        ACCEPT_LOGGER.error(
            "Socket accept failed",
            extra={"event": "accept_error", "error_type": type(error).__name__},
        )
        return False


def _reject_if_draining(
    lifecycle: LifecycleState, client_socket: socket.socket
) -> bool:
    if not lifecycle.is_draining():
        return False
    send_response(client_socket, draining_response(SECURITY_HEADERS))
    client_socket.close()
    return True


def _run_accept_loop(
    server_socket: socket.socket,
    lifecycle: LifecycleState,
    connection_limiter: ConnectionLimiter,
    handler_context: WorkerContext,
) -> None:
    while True:
        accepted = _accept_client(server_socket, lifecycle)
        if accepted is None:
            break
        if accepted is False:
            continue

        client_socket, client_address = accepted
        if _reject_if_draining(lifecycle, client_socket):
            continue

        _handle_accepted_client(
            client_socket, client_address, connection_limiter, handler_context
        )


def _finish_shutdown(
    server_socket: socket.socket,
    config: ServerConfig,
    lifecycle: LifecycleState,
) -> None:
    server_socket.close()
    ACCEPT_LOGGER.info(
        "Waiting for active connections to complete",
        extra={
            "event": "shutdown_waiting",
            "grace_seconds": config.shutdown_grace_seconds,
        },
    )
    lifecycle.wait_for_workers(config.shutdown_grace_seconds)
    ACCEPT_LOGGER.info("Server shutdown complete", extra={"event": "server_stopped"})


def run_server(
    args: argparse.Namespace, config: ServerConfig, lifecycle: LifecycleState
) -> None:
    """Create listening socket and handle client lifecycle."""

    server_socket = create_server_socket(args)

    ACCEPT_LOGGER.info(
        "Server listening for connections",
        extra={
            "event": "server_listening",
            "host": args.host,
            "port": args.port,
            "tls": bool(args.cert and args.key),
        },
    )

    connection_limiter = ConnectionLimiter(
        args.max_connections,
        args.max_connections_per_ip,
    )
    handler_context = _create_worker_context(
        args, config, lifecycle, connection_limiter
    )

    try:
        _run_accept_loop(
            server_socket,
            lifecycle,
            connection_limiter,
            handler_context,
        )
    finally:
        _finish_shutdown(server_socket, config, lifecycle)

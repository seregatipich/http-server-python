"""Composition root wiring transport collaborators across layers."""

import argparse
import logging
import signal
from dataclasses import dataclass
from typing import Optional

from pyhttpd.adapters.config.cli_args import ServerConfig
from pyhttpd.adapters.lifecycle import ServerLifecycle
from pyhttpd.adapters.logging.setup import configure_logging
from pyhttpd.adapters.ratelimit.token_bucket import TokenBucketLimiter
from pyhttpd.adapters.tls import create_server_socket
from pyhttpd.adapters.transport.connection_limiter import ConnectionLimiter
from pyhttpd.adapters.transport.context import WorkerContext
from pyhttpd.adapters.transport.server import run_server
from pyhttpd.domain import CorsConfig, LifecycleState, TokenBucketSettings

MAIN_LOGGER = logging.getLogger("http_server.main")


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


@dataclass
class Server:
    """Fully wired server ready to accept connections."""

    server_socket: object
    args: argparse.Namespace
    config: ServerConfig
    lifecycle: LifecycleState
    handler_context: WorkerContext
    connection_limiter: ConnectionLimiter

    def serve(self) -> None:
        """Run the accept loop on the listening socket."""
        run_server(
            self.server_socket,
            self.args,
            self.config,
            self.lifecycle,
            self.handler_context,
            self.connection_limiter,
        )


def build_server(args: argparse.Namespace) -> Server:
    """Configure runtime, register signals, and wire the server collaborators."""
    configure_logging(args.log_level, args.log_destination)

    config = ServerConfig(
        socket_timeout=args.socket_timeout,
        shutdown_grace_seconds=args.shutdown_grace_seconds,
    )
    lifecycle = ServerLifecycle()

    def shutdown_handler(signum: int, _frame) -> None:
        MAIN_LOGGER.info(
            "Shutdown signal received",
            extra={"event": "shutdown_signal_received", "signal": signum},
        )
        lifecycle.begin_draining()

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    MAIN_LOGGER.info(
        "HTTP server starting",
        extra={
            "event": "server_starting",
            "host": args.host,
            "port": args.port,
            "directory": args.directory,
            "log_destination": args.log_destination,
            "log_level": args.log_level,
            "tls": bool(args.cert and args.key),
            "socket_timeout": config.socket_timeout,
            "shutdown_grace_seconds": config.shutdown_grace_seconds,
        },
    )

    server_socket = create_server_socket(args)
    connection_limiter = ConnectionLimiter(
        args.max_connections,
        args.max_connections_per_ip,
    )
    handler_context = _create_worker_context(
        args, config, lifecycle, connection_limiter
    )
    return Server(
        server_socket=server_socket,
        args=args,
        config=config,
        lifecycle=lifecycle,
        handler_context=handler_context,
        connection_limiter=connection_limiter,
    )

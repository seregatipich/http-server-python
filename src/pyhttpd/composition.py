"""Composition root: validate config, register signals, and start the server."""

import argparse
import logging
import signal
import socket
from dataclasses import dataclass

from pyhttpd.adapters.config.cli_args import ServerConfig
from pyhttpd.adapters.lifecycle import ServerLifecycle
from pyhttpd.adapters.logging.setup import configure_logging
from pyhttpd.adapters.tls import create_server_socket
from pyhttpd.adapters.transport.connection_limiter import ConnectionLimiter
from pyhttpd.adapters.transport.context import WorkerContext
from pyhttpd.adapters.transport.server import run_server
from pyhttpd.application.config_validation import validate_startup_config
from pyhttpd.domain import LifecycleState
from pyhttpd.wiring import (
    _create_metrics_sink,
    _create_worker_context,
    register_config_reload,
)

MAIN_LOGGER = logging.getLogger("http_server.main")


@dataclass
class Server:
    """Fully wired server ready to accept connections."""

    server_socket: socket.socket
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


def _validate_or_exit(args: argparse.Namespace) -> None:
    config_errors = validate_startup_config(args)
    if not config_errors:
        return
    for message in config_errors:
        MAIN_LOGGER.critical(
            "Invalid configuration",
            extra={"event": "config_invalid", "error_type": message},
        )
    raise SystemExit(f"Invalid configuration: {'; '.join(config_errors)}")


def _register_shutdown(lifecycle: ServerLifecycle) -> None:
    def shutdown_handler(signum: int, _frame) -> None:
        MAIN_LOGGER.info(
            "Shutdown signal received",
            extra={"event": "shutdown_signal_received", "signal": signum},
        )
        lifecycle.begin_draining()

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)


def build_server(args: argparse.Namespace) -> Server:
    """Configure runtime, register signals, and wire the server collaborators."""
    configure_logging(args.log_level, args.log_destination)
    _validate_or_exit(args)

    config = ServerConfig(
        socket_timeout=args.socket_timeout,
        shutdown_grace_seconds=args.shutdown_grace_seconds,
    )
    lifecycle = ServerLifecycle()
    _register_shutdown(lifecycle)

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
            "auth_mode": args.auth_mode,
            "metrics": args.metrics,
        },
    )

    server_socket = create_server_socket(args)
    connection_limiter = ConnectionLimiter(
        args.max_connections,
        args.max_connections_per_ip,
    )
    handler_context = _create_worker_context(
        args, config, lifecycle, connection_limiter, _create_metrics_sink(args)
    )
    register_config_reload(args, handler_context)
    return Server(
        server_socket=server_socket,
        args=args,
        config=config,
        lifecycle=lifecycle,
        handler_context=handler_context,
        connection_limiter=connection_limiter,
    )

"""HTTP server entry point."""

import logging
import signal
import sys

from server.bootstrap.config import parse_cli_args, ServerConfig
from server.bootstrap.logging_setup import configure_logging
from server.domain.correlation_id import CorrelationLoggerAdapter
from server.lifecycle.state import ServerLifecycle
from server.transport.accept_loop import run_server

SERVER_LOGGER = CorrelationLoggerAdapter(logging.getLogger("http_server.server"), {})


def main() -> None:
    """Start the HTTP server and spawn worker threads per connection."""
    args = parse_cli_args(sys.argv[1:])
    configure_logging(args.log_level, args.log_destination)

    config = ServerConfig(
        socket_timeout=args.socket_timeout,
        shutdown_grace_seconds=args.shutdown_grace_seconds,
    )
    lifecycle = ServerLifecycle()

    def shutdown_handler(signum: int, _frame) -> None:
        SERVER_LOGGER.info("Received shutdown signal", extra={"signal": signum})
        lifecycle.begin_draining()

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    SERVER_LOGGER.info(
        "Starting HTTP server",
        extra={
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
    run_server(args, config, lifecycle)


if __name__ == "__main__":
    main()

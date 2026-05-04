"""HTTP server entry point."""

import logging
import signal
import sys

from server.bootstrap import ServerConfig, configure_logging, parse_cli_args
from server.lifecycle import ServerLifecycle
from server.transport import run_server

MAIN_LOGGER = logging.getLogger("http_server.main")


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
    run_server(args, config, lifecycle)


if __name__ == "__main__":
    main()

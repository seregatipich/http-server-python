"""Shared structured logging for the transport worker."""

import logging

from pyhttpd.adapters.logging.correlation_adapter import CorrelationLoggerAdapter

WORKER_LOGGER = CorrelationLoggerAdapter(
    logging.getLogger("http_server.transport.worker"), {}
)


class _PortLogger:  # pylint: disable=too-few-public-methods
    """Adapt the correlation logger to the structured ports.Logger interface."""

    def __init__(self, adapter: CorrelationLoggerAdapter) -> None:
        self._adapter = adapter

    def log(self, level: int, event: str, **fields: object) -> None:
        """Emit a structured log event through the correlation adapter."""
        self._adapter.log(level, event, extra={"event": event, **fields})


WORKER_PORT_LOGGER = _PortLogger(WORKER_LOGGER)


def log_worker_error(error: Exception, client_addr_str: str) -> None:
    """Log an unexpected worker failure with structured context."""
    WORKER_LOGGER.error(
        "Unexpected error in worker",
        extra={
            "event": "worker_error",
            "client": client_addr_str,
            "error_type": type(error).__name__,
            "error": str(error),
        },
        exc_info=True,
    )

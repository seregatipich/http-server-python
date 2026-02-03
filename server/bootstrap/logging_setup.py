"""Logging configuration utilities for the HTTP server."""

import json
import logging
import re
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Union

from server.domain.correlation_id import CorrelationLoggerAdapter

LOGGER_NAME = "http_server"
LOG_FORMAT = "%(asctime)s %(levelname)s [%(correlation_id)s] %(name)s :: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 5

SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(authorization|token|key|signature|password|secret|api[_-]?key)"),
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),
    re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),
]


def redact_sensitive(value: str) -> str:
    """Redact sensitive data from log values."""
    if not value:
        return value

    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(value):
            return "[REDACTED]"

    return value


class CorrelationIdFilter(logging.Filter):  # pylint: disable=too-few-public-methods
    """Ensure correlation_id field exists in log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "correlation_id"):
            record.correlation_id = "-"
        return True


class JsonFormatter(logging.Formatter):
    """JSON formatter with stable key ordering for structured logging."""

    def __init__(self, datefmt: Optional[str] = None):
        """Initialize JSON formatter with optional date format."""
        super().__init__(datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with stable key ordering."""
        log_data = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "correlation_id": getattr(record, "correlation_id", "-"),
            "component": getattr(record, "component", "unknown"),
            "message": record.getMessage(),
        }

        if hasattr(record, "event"):
            log_data["event"] = record.event

        extra_keys = [
            "client",
            "connection_id",
            "route",
            "status_code",
            "limit_type",
            "window_seconds",
            "remaining_tokens",
            "bytes_in",
            "bytes_out",
            "duration_ms",
            "error_type",
            "errno",
            "rate_limit_headers",
            "host",
            "port",
            "directory",
            "log_destination",
            "log_level",
            "tls",
            "socket_timeout",
            "shutdown_grace_seconds",
            "signal",
        ]

        for key in extra_keys:
            if hasattr(record, key):
                value = getattr(record, key)
                if isinstance(value, str):
                    value = redact_sensitive(value)
                log_data[key] = value

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, sort_keys=True)


def _resolve_level(level_name: str) -> int:
    """Translate text level names into logging module numeric levels."""
    level = getattr(logging, level_name.upper(), None)
    if isinstance(level, int):
        return level
    return logging.INFO


def _build_handler(
    destination: Optional[str], level: int, use_json: bool = True
) -> logging.Handler:
    """Create a stdout or rotating file handler for the configured logger."""
    if destination and destination.lower() != "stdout":
        target_path = Path(destination)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            target_path, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT
        )
    else:
        handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    if use_json:
        handler.setFormatter(JsonFormatter(DATE_FORMAT))
    else:
        handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

    handler.addFilter(CorrelationIdFilter())
    return handler


def configure_logging(
    level: str = "INFO", destination: Optional[str] = None, use_json: bool = True
) -> Union[logging.Logger, CorrelationLoggerAdapter]:
    """Configure and return the project logger with the requested handler."""
    logger = logging.getLogger(LOGGER_NAME)
    numeric_level = _resolve_level(level)
    logger.setLevel(numeric_level)
    logger.propagate = False

    for handler in list(logger.handlers):
        handler.close()
    logger.handlers.clear()

    handler = _build_handler(destination, numeric_level, use_json)
    logger.addHandler(handler)
    return CorrelationLoggerAdapter(logger, {})

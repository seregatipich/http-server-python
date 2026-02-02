"""Logging configuration utilities for the HTTP server."""

import logging
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


class CorrelationIdFilter(logging.Filter):  # pylint: disable=too-few-public-methods
    """Ensure correlation_id field exists in log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "correlation_id"):
            record.correlation_id = "-"
        return True


def _resolve_level(level_name: str) -> int:
    """Translate text level names into logging module numeric levels."""
    level = getattr(logging, level_name.upper(), None)
    if isinstance(level, int):
        return level
    return logging.INFO


def _build_handler(destination: Optional[str], level: int) -> logging.Handler:
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
    handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    handler.addFilter(CorrelationIdFilter())
    return handler


def configure_logging(
    level: str = "INFO", destination: Optional[str] = None
) -> Union[logging.Logger, CorrelationLoggerAdapter]:
    """Configure and return the project logger with the requested handler."""
    logger = logging.getLogger(LOGGER_NAME)
    numeric_level = _resolve_level(level)
    logger.setLevel(numeric_level)
    logger.propagate = False

    for handler in list(logger.handlers):
        handler.close()
    logger.handlers.clear()

    handler = _build_handler(destination, numeric_level)
    logger.addHandler(handler)
    return CorrelationLoggerAdapter(logger, {})

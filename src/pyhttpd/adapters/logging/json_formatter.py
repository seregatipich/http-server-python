"""JSON log formatter with stable key ordering."""

import json
import logging
from typing import Optional

from pyhttpd.adapters.logging.redaction import redact_sensitive


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

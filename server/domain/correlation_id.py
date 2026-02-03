"""Request correlation ID management using contextvars."""

import contextvars
import logging
import uuid
from typing import Any, MutableMapping, Optional

_correlation_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "correlation_id", default=None
)


def generate_correlation_id() -> str:
    """Generate a new correlation ID using UUID4."""
    return str(uuid.uuid4())


def get_correlation_id() -> Optional[str]:
    """Retrieve the current correlation ID from context."""
    return _correlation_id_var.get()


def set_correlation_id(correlation_id: str) -> None:
    """Store a correlation ID in the current context."""
    _correlation_id_var.set(correlation_id)


def clear_correlation_id() -> None:
    """Remove the correlation ID from the current context."""
    _correlation_id_var.set(None)


class CorrelationLoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that automatically injects correlation ID and component into log records."""

    def process(
        self, msg: str, kwargs: MutableMapping[str, Any]
    ) -> tuple[str, MutableMapping[str, Any]]:
        """Add correlation_id and component to the extra dict."""
        if "extra" not in kwargs:
            kwargs["extra"] = {}
        else:
            kwargs["extra"] = dict(kwargs["extra"])

        correlation_id = get_correlation_id()
        kwargs["extra"]["correlation_id"] = (
            correlation_id if correlation_id is not None else "-"
        )

        logger_name = self.logger.name
        if logger_name.startswith("http_server."):
            component = logger_name[len("http_server.") :]
        else:
            component = logger_name
        kwargs["extra"]["component"] = component

        return msg, kwargs

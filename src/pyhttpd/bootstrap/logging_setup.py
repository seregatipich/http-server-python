"""Backward-compatibility shim; logging setup now lives in adapters."""

from pyhttpd.adapters.logging.setup import (
    CorrelationIdFilter,
    JsonFormatter,
    configure_logging,
    redact_sensitive,
)

__all__ = [
    "CorrelationIdFilter",
    "JsonFormatter",
    "configure_logging",
    "redact_sensitive",
]

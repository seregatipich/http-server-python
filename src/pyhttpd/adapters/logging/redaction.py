"""Sensitive-data redaction for structured logging."""

import re

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

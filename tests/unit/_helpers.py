"""Shared construction helpers for unit tests."""

from pyhttpd.application import RequestContext
from pyhttpd.domain import HttpRequest

PASSTHROUGH = object()


def make_request(
    path="/", method="GET", headers=None, body=b"", query="", raw_path=""
) -> HttpRequest:
    """Build a minimal HttpRequest test double with sane defaults."""
    return HttpRequest(
        method=method,
        path=path,
        headers=headers or {},
        body=body,
        query=query,
        raw_path=raw_path,
    )


def make_context(correlation_id=None) -> RequestContext:
    """Build a minimal RequestContext for handler and chain invocation."""
    return RequestContext(correlation_id=correlation_id, start_ns=0)


class RecordingLogger:  # pylint: disable=too-few-public-methods
    """Logger spy capturing each structured log call."""

    def __init__(self):
        self.events = []

    def log(self, level, event, **fields):
        """Record a structured log event."""
        self.events.append((level, event, fields))

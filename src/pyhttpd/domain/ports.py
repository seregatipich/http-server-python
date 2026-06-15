"""Structural protocols for domain dependencies."""

from typing import Protocol

from pyhttpd.domain.ratelimit import RateLimitDecision


class Clock(Protocol):
    """Source of monotonic time in nanoseconds."""

    def now_ns(self) -> int:
        """Return the current time in nanoseconds."""


class IdGenerator(Protocol):
    """Generator of unique identifiers."""

    def new_id(self) -> str:
        """Return a new unique identifier."""


class RateLimiter(Protocol):
    """Rate limiter that consumes a token for a given key."""

    def consume(self, key: str) -> RateLimitDecision:
        """Consume a token for the key and return the decision."""


class Logger(Protocol):
    """Structured logger sink."""

    def log(self, level: int, event: str, **fields: object) -> None:
        """Emit a structured log event."""


class DrainingState(Protocol):
    """Lifecycle behavior shared by the accept loop and health handler."""

    def is_draining(self) -> bool:
        """Return whether the server is draining active work."""

    def should_stop(self) -> bool:
        """Return whether the server should stop accepting work."""

    def wait_for_workers(self, timeout: float) -> bool:
        """Wait for active workers to complete."""

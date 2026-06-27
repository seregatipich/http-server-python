"""Structural protocols for domain dependencies."""

from typing import Dict, Mapping, Optional, Protocol

from pyhttpd.domain.principal import Principal
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


class Authenticator(Protocol):
    """Resolves request credentials into an authenticated principal."""

    @property
    def challenge(self) -> str:
        """Return the WWW-Authenticate challenge for rejected requests."""

    def authenticate(self, headers: Mapping[str, str]) -> Optional[Principal]:
        """Return the authenticated principal, or None when credentials fail."""


class SessionStore(Protocol):
    """Stores mutable session data keyed by a generated session identifier."""

    def create(self) -> str:
        """Create an empty session and return its identifier."""

    def get(self, session_id: str) -> Optional[Dict[str, object]]:
        """Return the session data, or None when missing or expired."""


class Channel(Protocol):
    """Bidirectional byte stream a handler may take over after the handshake.

    Defined without importing ``socket`` so the domain stays transport-agnostic;
    an adapter wraps the real connection to satisfy it.
    """

    def read(self, size: int) -> bytes:
        """Read up to ``size`` bytes; an empty result signals end of stream."""

    def write(self, data: bytes) -> None:
        """Write all of ``data`` to the peer."""

    def close(self) -> None:
        """Close the underlying connection."""


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

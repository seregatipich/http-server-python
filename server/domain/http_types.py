"""Shared HTTP type definitions to avoid circular imports."""

from dataclasses import dataclass
from typing import Iterable, Optional, Protocol

DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024
HEADER_DELIMITER = b"\r\n\r\n"
FILES_ENDPOINT_PREFIX = "/files/"
ALLOWED_METHODS = {"GET", "POST", "OPTIONS"}
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
}


class RequestEntityTooLarge(Exception):
    """Raised when a request body exceeds configured limits."""


class LifecycleState(Protocol):
    """Lifecycle behavior shared by the accept loop and health handler."""

    def should_stop(self) -> bool:
        """Return whether the server should stop accepting work."""

    def is_draining(self) -> bool:
        """Return whether the server is draining active work."""

    def wait_for_workers(self, timeout: float) -> bool:
        """Wait for active workers to complete."""


@dataclass
class HttpRequest:
    """Represents a parsed HTTP request."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass
class HttpResponse:
    """Represents an HTTP response to be sent to a client."""

    status_line: str
    headers: dict[str, str]
    body: bytes
    close_connection: bool
    body_iter: Optional[Iterable[bytes]] = None
    use_chunked: bool = False


def should_close(headers: dict[str, str]) -> bool:
    """Determine whether the connection should be closed after responding."""
    return headers.get("connection", "").lower() == "close"


def format_client_address(client_address: tuple[str, int]) -> str:
    """Return a stable host:port string for logs."""
    return f"{client_address[0]}:{client_address[1]}"

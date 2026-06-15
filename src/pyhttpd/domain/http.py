"""HTTP request and response value types."""

from dataclasses import dataclass
from typing import Iterable, Optional

HEADER_DELIMITER = b"\r\n\r\n"


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

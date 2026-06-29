"""HTTP request and response value types."""

from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from pyhttpd.domain.ports import Channel


@dataclass
class HttpRequest:
    """Represents a parsed HTTP request."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    query: str = ""
    raw_path: str = ""


@dataclass
class HttpResponse:  # pylint: disable=too-many-instance-attributes
    """Represents an HTTP response to be sent to a client."""

    status_line: str
    headers: dict[str, str]
    body: bytes
    close_connection: bool
    body_iter: Optional[Iterable[bytes]] = None
    use_chunked: bool = False
    content_length: Optional[int] = None
    streaming: bool = False
    upgrade: Optional[Callable[[Channel], None]] = None


def should_close(headers: dict[str, str]) -> bool:
    """Determine whether the connection should be closed after responding."""
    return headers.get("connection", "").lower() == "close"

"""WebSocket opening-handshake helpers (RFC 6455 section 4)."""

import base64
import hashlib
from typing import Mapping

WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def compute_accept(key: str) -> str:
    """Return the Sec-WebSocket-Accept value for a client's Sec-WebSocket-Key."""
    digest = hashlib.sha1(
        (key + WEBSOCKET_GUID).encode(), usedforsecurity=False
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def is_websocket_upgrade(headers: Mapping[str, str]) -> bool:
    """Return whether the headers request a version-13 WebSocket upgrade."""
    return (
        headers.get("upgrade", "").lower() == "websocket"
        and "upgrade" in headers.get("connection", "").lower()
        and headers.get("sec-websocket-version", "") == "13"
        and bool(headers.get("sec-websocket-key"))
    )

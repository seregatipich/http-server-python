"""WebSocket opening-handshake helpers (RFC 6455 section 4)."""

import base64
import binascii
import hashlib
from typing import Mapping

WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WEBSOCKET_VERSION = "13"


def compute_accept(key: str) -> str:
    """Return the Sec-WebSocket-Accept value for a client's Sec-WebSocket-Key."""
    digest = hashlib.sha1(
        (key + WEBSOCKET_GUID).encode(), usedforsecurity=False
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def is_valid_sec_websocket_key(key: str) -> bool:
    """Return whether Sec-WebSocket-Key is base64 of exactly 16 bytes (RFC 6455 4.1)."""
    try:
        return len(base64.b64decode(key, validate=True)) == 16
    except (binascii.Error, ValueError):
        return False


def requests_websocket_upgrade(headers: Mapping[str, str]) -> bool:
    """Return whether the request is attempting a WebSocket upgrade at all."""
    return (
        headers.get("upgrade", "").lower() == "websocket"
        and "upgrade" in headers.get("connection", "").lower()
    )


def is_websocket_upgrade(headers: Mapping[str, str]) -> bool:
    """Return whether the headers request a valid version-13 WebSocket upgrade."""
    return (
        requests_websocket_upgrade(headers)
        and headers.get("sec-websocket-version", "") == WEBSOCKET_VERSION
        and is_valid_sec_websocket_key(headers.get("sec-websocket-key", ""))
    )

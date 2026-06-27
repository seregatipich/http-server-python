"""Pure WebSocket protocol primitives: frame codec and handshake helpers."""

from pyhttpd.domain.websocket.frame import (
    MAX_PAYLOAD_BYTES,
    OPCODE_BINARY,
    OPCODE_CLOSE,
    OPCODE_CONTINUATION,
    OPCODE_PING,
    OPCODE_PONG,
    OPCODE_TEXT,
    Frame,
    decode_frame,
    encode_frame,
    is_control_opcode,
)
from pyhttpd.domain.websocket.handshake import (
    WEBSOCKET_GUID,
    compute_accept,
    is_websocket_upgrade,
)

__all__ = [
    "MAX_PAYLOAD_BYTES",
    "OPCODE_BINARY",
    "OPCODE_CLOSE",
    "OPCODE_CONTINUATION",
    "OPCODE_PING",
    "OPCODE_PONG",
    "OPCODE_TEXT",
    "Frame",
    "WEBSOCKET_GUID",
    "compute_accept",
    "decode_frame",
    "encode_frame",
    "is_control_opcode",
    "is_websocket_upgrade",
]

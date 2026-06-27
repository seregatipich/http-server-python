"""HTTP/2 connection driver bridging streams to the application chain.

Speaks the HTTP/2 framing layer over a Channel: consumes the preface, exchanges
SETTINGS, reassembles each stream's HEADERS(+CONTINUATION)+DATA into an
HttpRequest, runs the existing middleware chain, and writes the HttpResponse
back as HEADERS+DATA. Streams are processed as they complete; outbound DATA
respects the peer's flow-control window.
"""

import struct
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote

from pyhttpd.application.context import RequestContext
from pyhttpd.application.frame_stream import BufferedFrameReader
from pyhttpd.domain import Channel, HttpRequest, HttpResponse
from pyhttpd.domain.http2.frames import (
    CONNECTION_PREFACE,
    CONTINUATION,
    DATA,
    FLAG_ACK,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FLAG_PADDED,
    FLAG_PRIORITY,
    GOAWAY,
    HEADERS,
    PING,
    PRIORITY,
    RST_STREAM,
    SETTINGS,
    WINDOW_UPDATE,
    Frame,
    decode_frame,
    encode_frame,
)
from pyhttpd.domain.http2.hpack import Decoder, encode_headers

READ_SIZE = 65536
MAX_FRAME_SIZE = 16384
INITIAL_WINDOW = 65535
ERROR_PROTOCOL = 1
_SKIP_RESPONSE_HEADERS = frozenset(
    {"connection", "keep-alive", "transfer-encoding", "upgrade", "content-length"}
)

Dispatch = Callable[[HttpRequest, RequestContext], HttpResponse]
ContextFactory = Callable[[], RequestContext]


class _Stream:
    """Accumulates a single HTTP/2 stream's header block and body."""

    def __init__(self) -> None:
        self.header_block = bytearray()
        self.body = bytearray()


class Http2Connection:  # pylint: disable=too-many-instance-attributes
    """Drives one HTTP/2 connection, dispatching each stream to the chain."""

    def __init__(
        self, channel: Channel, dispatch: Dispatch, make_context: ContextFactory
    ) -> None:
        self._channel = channel
        self._dispatch = dispatch
        self._make_context = make_context
        self._decoder = Decoder()
        self._reader: BufferedFrameReader[Frame] = BufferedFrameReader(
            channel, decode_frame, READ_SIZE
        )
        self._streams: Dict[int, _Stream] = {}
        self._send_window = INITIAL_WINDOW
        self._dispatch_table = {
            SETTINGS: self._on_settings,
            PING: self._on_ping,
            WINDOW_UPDATE: self._on_window_update,
            GOAWAY: self._on_goaway,
            RST_STREAM: self._on_reset,
            PRIORITY: self._on_reset,
            HEADERS: self._on_headers,
            CONTINUATION: self._on_continuation,
            DATA: self._on_data,
        }

    def serve(self, initial: bytes = b"") -> None:
        """Run the connection until the peer disconnects or sends GOAWAY."""
        self._reader = BufferedFrameReader(
            self._channel, decode_frame, READ_SIZE, initial
        )
        if self._reader.read_exact(len(CONNECTION_PREFACE)) != CONNECTION_PREFACE:
            return
        self._write(SETTINGS, 0, 0, b"")
        try:
            self._run()
        except (OSError, ConnectionError, ValueError):
            pass

    def _run(self) -> None:
        while True:
            frame = self._reader.next_frame()
            if frame is None or not self._handle(frame):
                return

    def _handle(self, frame: Frame) -> bool:
        return self._dispatch_table.get(frame.frame_type, _ignore_frame)(frame)

    def _on_settings(self, frame: Frame) -> bool:
        if not frame.flags & FLAG_ACK:
            self._write(SETTINGS, FLAG_ACK, 0, b"")
        return True

    def _on_ping(self, frame: Frame) -> bool:
        if not frame.flags & FLAG_ACK:
            self._write(PING, FLAG_ACK, 0, frame.payload)
        return True

    def _on_window_update(self, frame: Frame) -> bool:
        if frame.stream_id == 0:
            self._send_window += struct.unpack("!I", frame.payload[:4])[0]
        return True

    def _on_goaway(self, _frame: Frame) -> bool:
        return False

    def _on_reset(self, frame: Frame) -> bool:
        self._streams.pop(frame.stream_id, None)
        return True

    def _on_headers(self, frame: Frame) -> bool:
        stream = self._streams.setdefault(frame.stream_id, _Stream())
        stream.header_block.extend(_header_block_fragment(frame))
        if frame.flags & FLAG_END_STREAM:
            return self._complete(frame.stream_id)
        return True

    def _on_continuation(self, frame: Frame) -> bool:
        stream = self._streams.get(frame.stream_id)
        if stream is not None:
            stream.header_block.extend(frame.payload)
        return True

    def _on_data(self, frame: Frame) -> bool:
        stream = self._streams.get(frame.stream_id)
        if stream is None:
            return True
        stream.body.extend(_data_payload(frame))
        if frame.flags & FLAG_END_STREAM:
            return self._complete(frame.stream_id)
        return True

    def _complete(self, stream_id: int) -> bool:
        stream = self._streams.pop(stream_id, None)
        if stream is None:
            return True
        headers = self._decoder.decode(bytes(stream.header_block))
        request = _build_request(headers, bytes(stream.body))
        if request is None:
            self._write(RST_STREAM, 0, stream_id, struct.pack("!I", ERROR_PROTOCOL))
            return True
        response = self._dispatch(request, self._make_context())
        self._send_response(stream_id, request, response)
        return True

    def _send_response(
        self, stream_id: int, request: HttpRequest, response: HttpResponse
    ) -> None:
        block = encode_headers(_response_headers(response))
        body = b"" if request.method == "HEAD" else _materialize_body(response)
        if not body:
            self._write(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, stream_id, block)
            return
        self._write(HEADERS, FLAG_END_HEADERS, stream_id, block)
        self._send_data(stream_id, body)

    def _send_data(self, stream_id: int, body: bytes) -> None:
        offset = 0
        while offset < len(body):
            allowance = self._await_window()
            if allowance <= 0:
                return
            chunk = body[offset : offset + min(MAX_FRAME_SIZE, allowance)]
            offset += len(chunk)
            self._send_window -= len(chunk)
            flags = FLAG_END_STREAM if offset >= len(body) else 0
            self._write(DATA, flags, stream_id, chunk)

    def _await_window(self) -> int:
        while self._send_window <= 0:
            frame = self._reader.next_frame()
            if frame is None or not self._handle(frame):
                return 0
        return self._send_window

    def _write(
        self, frame_type: int, flags: int, stream_id: int, payload: bytes
    ) -> None:
        self._channel.write(encode_frame(frame_type, flags, stream_id, payload))


def _ignore_frame(_frame: Frame) -> bool:
    return True


def _header_block_fragment(frame: Frame) -> bytes:
    payload = frame.payload
    offset = 0
    pad_length = 0
    if frame.flags & FLAG_PADDED:
        pad_length = payload[0]
        offset = 1
    if frame.flags & FLAG_PRIORITY:
        offset += 5
    end = len(payload) - pad_length
    return payload[offset:end]


def _data_payload(frame: Frame) -> bytes:
    if not frame.flags & FLAG_PADDED:
        return frame.payload
    pad_length = frame.payload[0]
    return frame.payload[1 : len(frame.payload) - pad_length]


def _build_request(
    headers: List[Tuple[str, str]], body: bytes
) -> Optional[HttpRequest]:
    pseudo: Dict[str, str] = {}
    regular: Dict[str, str] = {}
    for name, value in headers:
        if name.startswith(":"):
            pseudo[name] = value
        else:
            regular[name] = value
    method = pseudo.get(":method")
    target = pseudo.get(":path")
    if not method or not target:
        return None
    authority = pseudo.get(":authority")
    if authority:
        regular.setdefault("host", authority)
    path, _, query = target.partition("?")
    return HttpRequest(method, unquote(path), regular, body, query)


def _response_headers(response: HttpResponse) -> List[Tuple[str, str]]:
    headers: List[Tuple[str, str]] = [(":status", str(_status_code(response)))]
    for name, value in response.headers.items():
        if name.lower() not in _SKIP_RESPONSE_HEADERS:
            headers.append((name.lower(), value))
    return headers


def _status_code(response: HttpResponse) -> int:
    try:
        return int(response.status_line.split(" ", 2)[1])
    except (IndexError, ValueError):
        return 500


def _materialize_body(response: HttpResponse) -> bytes:
    if response.body_iter is not None:
        return b"".join(chunk for chunk in response.body_iter if chunk)
    return response.body

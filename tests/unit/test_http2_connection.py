"""Unit tests for the HTTP/2 connection driver (F13)."""

from typing import List, Tuple

from pyhttpd.adapters.http2.connection import MAX_FRAME_SIZE, Http2Connection
from pyhttpd.application import RequestContext
from pyhttpd.domain import HttpRequest, HttpResponse
from pyhttpd.domain.http2.frames import (
    CONNECTION_PREFACE,
    DATA,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    GOAWAY,
    HEADERS,
    PRIORITY,
    RST_STREAM,
    SETTINGS,
    WINDOW_UPDATE,
    decode_frame,
    encode_frame,
)
from pyhttpd.domain.http2.hpack import Decoder, encode_headers


class FakeChannel:
    def __init__(self, inbound: bytes) -> None:
        self._inbound = bytearray(inbound)
        self.outbound = bytearray()

    def read(self, size: int) -> bytes:
        chunk = bytes(self._inbound[:size])
        del self._inbound[:size]
        return chunk

    def write(self, data: bytes) -> None:
        self.outbound.extend(data)

    def close(self) -> None:
        pass


def _request_stream(headers: List[Tuple[str, str]]) -> bytes:
    block = encode_headers(headers)
    return (
        CONNECTION_PREFACE
        + encode_frame(SETTINGS, 0, 0, b"")
        + encode_frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, block)
    )


def _parse_frames(data: bytes):
    frames = []
    offset = 0
    while offset < len(data):
        decoded = decode_frame(data[offset:])
        if decoded is None:
            break
        frame, consumed = decoded
        frames.append(frame)
        offset += consumed
    return frames


def _run(
    inbound: bytes, dispatch, max_body_bytes: int = 5 * 1024 * 1024
) -> FakeChannel:
    channel = FakeChannel(inbound)
    Http2Connection(
        channel,
        dispatch,
        lambda: RequestContext(correlation_id=None, start_ns=0),
        max_body_bytes=max_body_bytes,
    ).serve()
    return channel


def _ok_dispatch(counter: dict):
    def dispatch(request: HttpRequest, _ctx) -> HttpResponse:
        counter["count"] = counter.get("count", 0) + 1
        counter["request"] = request
        return HttpResponse("HTTP/1.1 200 OK", {}, b"", False)

    return dispatch


def test_priority_frame_does_not_drop_an_open_stream() -> None:
    counter: dict = {}
    block = encode_headers(
        [(":method", "POST"), (":scheme", "http"), (":path", "/x"), ("host", "h")]
    )
    inbound = (
        CONNECTION_PREFACE
        + encode_frame(SETTINGS, 0, 0, b"")
        + encode_frame(HEADERS, FLAG_END_HEADERS, 1, block)
        + encode_frame(PRIORITY, 0, 1, b"\x00\x00\x00\x00\x10")
        + encode_frame(DATA, FLAG_END_STREAM, 1, b"hi")
    )
    _run(inbound, _ok_dispatch(counter))
    assert counter.get("count") == 1
    assert counter["request"].body == b"hi"


def test_data_exceeding_body_cap_is_rejected() -> None:
    counter: dict = {}
    block = encode_headers(
        [(":method", "POST"), (":scheme", "http"), (":path", "/x"), ("host", "h")]
    )
    inbound = (
        CONNECTION_PREFACE
        + encode_frame(SETTINGS, 0, 0, b"")
        + encode_frame(HEADERS, FLAG_END_HEADERS, 1, block)
        + encode_frame(DATA, FLAG_END_STREAM, 1, b"X" * 100)
    )
    channel = _run(inbound, _ok_dispatch(counter), max_body_bytes=10)
    assert counter.get("count") is None
    frames = _parse_frames(bytes(channel.outbound))
    assert any(f.frame_type == RST_STREAM for f in frames)


def test_oversized_frame_triggers_goaway() -> None:
    counter: dict = {}
    block = encode_headers(
        [(":method", "POST"), (":scheme", "http"), (":path", "/x"), ("host", "h")]
    )
    inbound = (
        CONNECTION_PREFACE
        + encode_frame(SETTINGS, 0, 0, b"")
        + encode_frame(HEADERS, FLAG_END_HEADERS, 1, block)
        + encode_frame(DATA, FLAG_END_STREAM, 1, b"X" * (MAX_FRAME_SIZE + 1))
    )
    channel = _run(inbound, _ok_dispatch(counter))
    assert counter.get("count") is None
    assert any(f.frame_type == GOAWAY for f in _parse_frames(bytes(channel.outbound)))


def test_headers_on_even_stream_id_is_rejected() -> None:
    counter: dict = {}
    block = encode_headers(
        [(":method", "GET"), (":scheme", "http"), (":path", "/x"), ("host", "h")]
    )
    inbound = (
        CONNECTION_PREFACE
        + encode_frame(SETTINGS, 0, 0, b"")
        + encode_frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 2, block)
    )
    channel = _run(inbound, _ok_dispatch(counter))
    assert counter.get("count") is None
    assert any(f.frame_type == GOAWAY for f in _parse_frames(bytes(channel.outbound)))


def test_short_window_update_does_not_crash() -> None:
    inbound = (
        CONNECTION_PREFACE
        + encode_frame(SETTINGS, 0, 0, b"")
        + encode_frame(WINDOW_UPDATE, 0, 0, b"\x00")
    )
    channel = _run(
        inbound, lambda r, c: HttpResponse("HTTP/1.1 200 OK", {}, b"", False)
    )
    assert any(f.frame_type == GOAWAY for f in _parse_frames(bytes(channel.outbound)))


def test_driver_dispatches_request_and_writes_response() -> None:
    captured = {}

    def dispatch(request: HttpRequest, _ctx) -> HttpResponse:
        captured["request"] = request
        return HttpResponse(
            "HTTP/1.1 200 OK", {"content-type": "text/plain"}, b"hello", False
        )

    inbound = _request_stream(
        [
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/echo/hi"),
            (":authority", "localhost"),
        ]
    )
    channel = _run(inbound, dispatch)

    assert captured["request"].method == "GET"
    assert captured["request"].path == "/echo/hi"
    assert captured["request"].headers["host"] == "localhost"

    frames = _parse_frames(bytes(channel.outbound))
    headers_frame = next(f for f in frames if f.frame_type == HEADERS)
    response_headers = dict(Decoder().decode(headers_frame.payload))
    assert response_headers[":status"] == "200"
    assert response_headers["content-type"] == "text/plain"

    data_frame = next(f for f in frames if f.frame_type == DATA)
    assert data_frame.payload == b"hello"
    assert data_frame.flags & FLAG_END_STREAM


def test_driver_handles_request_body() -> None:
    captured = {}

    def dispatch(request: HttpRequest, _ctx) -> HttpResponse:
        captured["body"] = request.body
        return HttpResponse("HTTP/1.1 200 OK", {}, b"", False)

    block = encode_headers(
        [(":method", "POST"), (":scheme", "http"), (":path", "/x"), ("host", "h")]
    )
    inbound = (
        CONNECTION_PREFACE
        + encode_frame(SETTINGS, 0, 0, b"")
        + encode_frame(HEADERS, FLAG_END_HEADERS, 1, block)
        + encode_frame(DATA, FLAG_END_STREAM, 1, b"payload")
    )
    _run(inbound, dispatch)
    assert captured["body"] == b"payload"


def test_driver_rejects_wrong_preface() -> None:
    channel = FakeChannel(b"NOT THE PREFACE........................")
    Http2Connection(
        channel,
        lambda r, c: HttpResponse("HTTP/1.1 200 OK", {}, b"", False),
        lambda: RequestContext(correlation_id=None, start_ns=0),
    ).serve()
    assert bytes(channel.outbound) == b""

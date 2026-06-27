"""Unit tests for the Server-Sent Events handler (F6)."""

from unittest.mock import patch

import pytest

from pyhttpd.application.handlers.sse import (
    _event_count,
    _event_stream,
    make_sse_handler,
)
from pyhttpd.domain import MethodNotAllowed
from tests.unit._helpers import RecordingLogger, make_context, make_request


class FakeDraining:
    """Minimal DrainingState double."""

    def __init__(self, draining: bool = False) -> None:
        self._draining = draining

    def is_draining(self) -> bool:
        return self._draining

    def should_stop(self) -> bool:
        return False

    def wait_for_workers(self, _timeout: float) -> bool:
        return True


def test_event_count_default_and_clamping() -> None:
    assert _event_count("") == 5
    assert _event_count("count=3") == 3
    assert _event_count("count=0") == 1
    assert _event_count("count=99999") == 1000
    assert _event_count("count=abc") == 5


def test_event_stream_emits_formatted_events() -> None:
    with patch("pyhttpd.application.handlers.sse.time.sleep"):
        events = list(_event_stream(FakeDraining(False), 3))
    assert events == [
        b"id: 1\nevent: tick\ndata: 1\n\n",
        b"id: 2\nevent: tick\ndata: 2\n\n",
        b"id: 3\nevent: tick\ndata: 3\n\n",
    ]


def test_event_stream_stops_immediately_when_draining() -> None:
    assert list(_event_stream(FakeDraining(True), 5)) == []


def test_handler_returns_streaming_event_stream_response() -> None:
    handler = make_sse_handler(FakeDraining(False), RecordingLogger())
    response = handler(make_request(path="/events", query="count=2"), make_context())

    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.headers["Content-Type"] == "text/event-stream"
    assert response.headers["Cache-Control"] == "no-cache"
    assert response.streaming is True
    assert response.use_chunked is True
    with patch("pyhttpd.application.handlers.sse.time.sleep"):
        assert len(list(response.body_iter)) == 2


def test_handler_rejects_non_get() -> None:
    handler = make_sse_handler(FakeDraining(False), RecordingLogger())
    with pytest.raises(MethodNotAllowed):
        handler(make_request(path="/events", method="POST"), make_context())

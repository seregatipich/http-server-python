"""Unit tests for the metrics collection middleware."""

import pytest

from pyhttpd.application import build_chain, make_metrics_middleware
from pyhttpd.domain import HttpResponse, InternalServerError, NotFound
from tests.unit._helpers import make_context, make_request


class RecordingSink:
    """Metrics sink spy capturing calls."""

    def __init__(self):
        self.requests = []
        self.errors = []
        self.in_flight = 0
        self.max_in_flight = 0

    def observe_request(self, method, route, status, latency_seconds):
        self.requests.append((method, route, status))

    def inc_error(self, method, route):
        self.errors.append((method, route))

    def inc_rejection(self, kind):
        pass

    def inc_in_flight(self):
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)

    def dec_in_flight(self):
        self.in_flight -= 1

    def render(self):
        return b""


def _route_label(request):
    return request.path


def _ok_terminal(request, ctx):
    return HttpResponse("HTTP/1.1 200 OK", {}, b"", close_connection=False)


def test_successful_request_is_observed_with_balanced_in_flight():
    """A successful request is recorded and the in-flight gauge returns to zero."""
    sink = RecordingSink()
    handler = build_chain([make_metrics_middleware(sink, _route_label)], _ok_terminal)

    handler(make_request("/", method="GET"), make_context())

    assert sink.requests == [("GET", "/", 200)]
    assert sink.max_in_flight == 1
    assert sink.in_flight == 0


def test_client_error_is_observed_but_not_counted_as_error():
    """A raised 4xx is recorded as a request but not as a server error."""
    sink = RecordingSink()

    def boom(request, ctx):
        raise NotFound("missing")

    handler = build_chain([make_metrics_middleware(sink, _route_label)], boom)

    with pytest.raises(NotFound):
        handler(make_request("/missing"), make_context())

    assert sink.errors == []
    assert sink.requests == [("GET", "/missing", 404)]
    assert sink.in_flight == 0


def test_server_error_increments_error_counter_and_reraises():
    """A raised 5xx is counted as an error and propagated."""
    sink = RecordingSink()

    def boom(request, ctx):
        raise InternalServerError("boom")

    handler = build_chain([make_metrics_middleware(sink, _route_label)], boom)

    with pytest.raises(InternalServerError):
        handler(make_request("/crash"), make_context())

    assert sink.errors == [("GET", "/crash")]
    assert sink.in_flight == 0


def test_metrics_path_is_not_self_instrumented():
    """Requests to /metrics are excluded from collection."""
    sink = RecordingSink()
    handler = build_chain([make_metrics_middleware(sink, _route_label)], _ok_terminal)

    handler(make_request("/metrics"), make_context())

    assert sink.requests == []
    assert sink.max_in_flight == 0

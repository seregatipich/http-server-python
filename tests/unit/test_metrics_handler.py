"""Unit tests for the /metrics route handler."""

from pyhttpd.adapters.metrics import LockingMetricsSink
from pyhttpd.application.handlers.metrics import make_metrics_handler
from tests.unit._helpers import make_context, make_request


def test_metrics_handler_renders_exposition_with_prometheus_content_type():
    """The handler returns the rendered exposition with the Prometheus media type."""
    sink = LockingMetricsSink()
    sink.observe_request("GET", "/", 200, 0.01)
    handler = make_metrics_handler(sink)

    response = handler(make_request("/metrics"), make_context())

    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.headers["Content-Type"] == (
        "text/plain; version=0.0.4; charset=utf-8"
    )
    assert b"http_requests_total" in response.body
    assert response.headers["Content-Security-Policy"] == "default-src 'self'"


def test_metrics_handler_honors_connection_close():
    """A Connection: close request closes the connection after the response."""
    sink = LockingMetricsSink()
    handler = make_metrics_handler(sink)

    response = handler(
        make_request("/metrics", headers={"connection": "close"}), make_context()
    )

    assert response.close_connection is True

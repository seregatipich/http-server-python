"""Unit tests for terminal application route handlers."""

import logging

from pyhttpd.application import (
    make_echo_handler,
    make_healthz_handler,
    make_user_agent_handler,
)
from pyhttpd.domain import CorsConfig, HttpResponse
from tests.unit._helpers import RecordingLogger, make_request


class FakeDrainingState:
    """Minimal DrainingState exposing a fixed draining flag."""

    def __init__(self, draining):
        self._draining = draining

    def is_draining(self):
        """Return the configured draining flag."""
        return self._draining

    def should_stop(self):
        """Return whether the server should stop accepting work."""
        return self._draining

    def wait_for_workers(self, _timeout):
        """Pretend all workers drained immediately."""
        return True


def test_echo_returns_path_suffix_as_text_plain(ctx):
    """Echo handler returns the /echo/ suffix as a text/plain 200."""
    handler = make_echo_handler(RecordingLogger())
    response = handler(make_request(path="/echo/hello-world"), ctx)
    assert isinstance(response, HttpResponse)
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.body == b"hello-world"
    assert response.headers["Content-Type"] == "text/plain"


def test_echo_handles_empty_suffix(ctx):
    """Echo handler returns an empty body when nothing follows /echo/."""
    handler = make_echo_handler(RecordingLogger())
    response = handler(make_request(path="/echo/"), ctx)
    assert response.body == b""
    assert "Content-Encoding" not in response.headers


def test_echo_logs_debug_event_with_content_length(ctx):
    """Echo handler emits a debug event carrying the content length."""
    logger = RecordingLogger()
    handler = make_echo_handler(logger)
    handler(make_request(path="/echo/abc"), ctx)
    assert logger.events == [(logging.DEBUG, "echo_request", {"content_length": 3})]


def test_echo_compresses_when_gzip_accepted(ctx):
    """Echo handler gzip-compresses the body when the client accepts gzip."""
    handler = make_echo_handler(RecordingLogger())
    response = handler(
        make_request(path="/echo/payload", headers={"accept-encoding": "gzip"}), ctx
    )
    assert response.headers["Content-Encoding"] == "gzip"
    assert response.body != b"payload"


def test_echo_applies_cors_headers_for_allowed_origin(ctx):
    """Echo handler reflects CORS headers when a cors_config is injected."""
    cors_config = CorsConfig(
        allowed_origins=["https://app.example.com"],
        allowed_methods=["GET"],
        allowed_headers=["content-type"],
        expose_headers=["x-trace"],
        allow_credentials=False,
        max_age=600,
    )
    handler = make_echo_handler(RecordingLogger(), cors_config)
    response = handler(
        make_request(path="/echo/x", headers={"origin": "https://app.example.com"}),
        ctx,
    )
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.example.com"


def test_echo_close_connection_follows_request_preference(ctx):
    """Echo handler honors a Connection: close request header."""
    handler = make_echo_handler(RecordingLogger())
    closing = handler(
        make_request(path="/echo/x", headers={"connection": "close"}), ctx
    )
    keep_alive = handler(make_request(path="/echo/x"), ctx)
    assert closing.close_connection is True
    assert keep_alive.close_connection is False


def test_user_agent_returns_header_value_as_text_plain(ctx):
    """User-Agent handler returns the User-Agent header value as text/plain."""
    handler = make_user_agent_handler(RecordingLogger())
    response = handler(
        make_request(path="/user-agent", headers={"user-agent": "curl/8.4.0"}), ctx
    )
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.body == b"curl/8.4.0"
    assert response.headers["Content-Type"] == "text/plain"


def test_user_agent_returns_empty_when_header_absent(ctx):
    """User-Agent handler returns an empty body when the header is missing."""
    handler = make_user_agent_handler(RecordingLogger())
    response = handler(make_request(path="/user-agent"), ctx)
    assert response.body == b""


def test_user_agent_logs_request_event(ctx):
    """User-Agent handler emits a debug request event with no extra fields."""
    logger = RecordingLogger()
    handler = make_user_agent_handler(logger)
    handler(make_request(path="/user-agent", headers={"user-agent": "x"}), ctx)
    assert logger.events == [(logging.DEBUG, "user_agent_request", {})]


def test_user_agent_compresses_when_gzip_accepted(ctx):
    """User-Agent handler gzip-compresses when the client accepts gzip."""
    handler = make_user_agent_handler(RecordingLogger())
    response = handler(
        make_request(
            path="/user-agent",
            headers={"user-agent": "agent", "accept-encoding": "gzip"},
        ),
        ctx,
    )
    assert response.headers["Content-Encoding"] == "gzip"


def test_healthz_returns_200_when_not_draining(ctx):
    """Healthz handler returns 200 with a keep-alive connection when healthy."""
    handler = make_healthz_handler(FakeDrainingState(False), RecordingLogger())
    response = handler(make_request(path="/healthz"), ctx)
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.body == b""
    assert response.close_connection is False


def test_healthz_returns_503_when_draining(ctx):
    """Healthz handler returns a closing 503 while the server is draining."""
    handler = make_healthz_handler(FakeDrainingState(True), RecordingLogger())
    response = handler(make_request(path="/healthz"), ctx)
    assert response.status_line == "HTTP/1.1 503 Service Unavailable"
    assert response.body == b"draining"
    assert response.headers["Connection"] == "close"
    assert response.close_connection is True


def test_healthz_treats_missing_draining_state_as_healthy(ctx):
    """Healthz handler reports 200 when no DrainingState is injected."""
    handler = make_healthz_handler(None, RecordingLogger())
    response = handler(make_request(path="/healthz"), ctx)
    assert response.status_line == "HTTP/1.1 200 OK"


def test_healthz_logs_check_event_with_draining_flag(ctx):
    """Healthz handler logs an info event reporting the draining flag."""
    logger = RecordingLogger()
    handler = make_healthz_handler(FakeDrainingState(True), logger)
    handler(make_request(path="/healthz"), ctx)
    assert logger.events == [(logging.INFO, "healthz_check", {"draining": True})]


def test_healthz_includes_security_headers(ctx):
    """Healthz handler always attaches the configured security headers."""
    handler = make_healthz_handler(FakeDrainingState(False), RecordingLogger())
    response = handler(make_request(path="/healthz"), ctx)
    assert response.headers["X-Content-Type-Options"] == "nosniff"

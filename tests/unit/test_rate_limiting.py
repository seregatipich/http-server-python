"""Unit tests for request rate limiting middleware."""

import socket
from unittest.mock import Mock

from pyhttpd.domain import HttpRequest, TokenBucketLimiter, TokenBucketSettings
from pyhttpd.pipeline.rate_limiting import apply_rate_limit


def make_request(headers: dict[str, str] | None = None) -> HttpRequest:
    """Build a minimal request for rate-limit middleware tests."""
    return HttpRequest("GET", "/", headers or {}, b"")


def make_limiter(dry_run: bool = False) -> TokenBucketLimiter:
    """Build a limiter that allows one request per window."""
    return TokenBucketLimiter(
        TokenBucketSettings(
            rate_limit=1,
            window_ms=1000,
            burst_capacity=1,
            dry_run=dry_run,
        ),
        time_provider=lambda: 0,
    )


def test_apply_rate_limit_no_limiter_allows_request() -> None:
    """Missing limiter should leave request processing untouched."""
    client_socket = Mock(spec=socket.socket)

    decision, should_stop, should_close = apply_rate_limit(
        None,
        "127.0.0.1",
        client_socket,
        ("127.0.0.1", 12345),
        make_request(),
    )

    assert decision is None
    assert should_stop is False
    assert should_close is False
    client_socket.sendall.assert_not_called()


def test_apply_rate_limit_allowed_request_returns_decision() -> None:
    """Allowed requests should return headers and continue processing."""
    client_socket = Mock(spec=socket.socket)

    decision, should_stop, should_close = apply_rate_limit(
        make_limiter(),
        "127.0.0.1",
        client_socket,
        ("127.0.0.1", 12345),
        make_request(),
    )

    assert decision is not None
    assert decision.allowed is True
    assert should_stop is False
    assert should_close is False
    client_socket.sendall.assert_not_called()


def test_apply_rate_limit_enforced_sends_429() -> None:
    """Exceeded limits should send a 429 and stop request processing."""
    limiter = make_limiter()
    client_socket = Mock(spec=socket.socket)
    apply_rate_limit(
        limiter,
        "127.0.0.1",
        client_socket,
        ("127.0.0.1", 12345),
        make_request(),
    )
    client_socket.reset_mock()

    decision, should_stop, should_close = apply_rate_limit(
        limiter,
        "127.0.0.1",
        client_socket,
        ("127.0.0.1", 12345),
        make_request(),
    )

    assert decision is None
    assert should_stop is True
    assert should_close is False
    payload = b"".join(call.args[0] for call in client_socket.sendall.call_args_list)
    assert b"HTTP/1.1 429 Too Many Requests" in payload
    assert b"Rate limit exceeded" in payload


def test_apply_rate_limit_dry_run_continues_processing() -> None:
    """Dry-run mode should report a decision without sending a 429."""
    limiter = make_limiter(dry_run=True)
    client_socket = Mock(spec=socket.socket)
    apply_rate_limit(
        limiter,
        "127.0.0.1",
        client_socket,
        ("127.0.0.1", 12345),
        make_request(),
    )

    decision, should_stop, should_close = apply_rate_limit(
        limiter,
        "127.0.0.1",
        client_socket,
        ("127.0.0.1", 12345),
        make_request(),
    )

    assert decision is not None
    assert decision.dry_run is True
    assert should_stop is False
    assert should_close is False
    client_socket.sendall.assert_not_called()

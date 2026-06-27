"""Goldens for Stage 4D: central 500 mapping and index traversal 403."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pyhttpd.adapters.transport import WorkerContext, handle_client
from pyhttpd.application import RequestContext, make_index_handler
from pyhttpd.domain import SECURITY_HEADERS, Forbidden, ForbiddenPath, HttpRequest
from tests.characterization.raw_client import parse_response


def _capturing_socket(request_bytes: bytes) -> tuple[MagicMock, list[bytes]]:
    """Return a mock client socket that serves one request and records sends."""
    client_socket = MagicMock()
    client_socket.recv.side_effect = [request_bytes, b""]
    sent: list[bytes] = []
    client_socket.sendall.side_effect = sent.append
    return client_socket, sent


def _bare_context() -> MagicMock:
    """Build a worker context with rate limiting and CORS disabled."""
    context = MagicMock(spec=WorkerContext)
    context.directory = "."
    context.lifecycle = MagicMock()
    context.lifecycle.is_draining.return_value = False
    context.config = MagicMock()
    context.cors_config = None
    context.rate_limiter = None
    context.connection_limiter = None
    context.authenticator = None
    context.session_store = None
    context.session_policy = None
    return context


class _BoomRouter:
    """Router that fails with a non-HttpError to exercise the 500 path."""

    def dispatch(self, request: HttpRequest, ctx: RequestContext):
        raise ValueError("handler exploded")


def test_unexpected_error_returns_500() -> None:
    """A non-HttpError raised while routing yields a 500 with no body or CORS."""
    client_socket, sent = _capturing_socket(
        b"GET /echo/boom HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    context = _bare_context()

    with patch(
        "pyhttpd.adapters.transport.worker.make_default_router",
        return_value=_BoomRouter(),
    ):
        handle_client(client_socket, ("127.0.0.1", 5555), context)

    status_line, headers, body = parse_response(b"".join(sent))

    assert status_line == "HTTP/1.1 500 Internal Server Error"
    for name, expected in SECURITY_HEADERS.items():
        assert headers[name] == expected
    assert headers["Content-Length"] == "0"
    assert headers["Connection"] == "close"
    assert "Access-Control-Allow-Origin" not in headers
    assert body == b""


def test_index_traversal_forbidden_403() -> None:
    """An index path escaping the sandbox is served as a 403 through the worker."""
    client_socket, sent = _capturing_socket(
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    context = _bare_context()

    with patch(
        "pyhttpd.application.handlers.files.resolve_sandbox_path",
        side_effect=ForbiddenPath(),
    ):
        handle_client(client_socket, ("127.0.0.1", 5556), context)

    status_line, headers, body = parse_response(b"".join(sent))

    assert status_line == "HTTP/1.1 403 Forbidden"
    for name, expected in SECURITY_HEADERS.items():
        assert headers[name] == expected
    assert headers["Content-Length"] == "0"
    assert body == b""


def test_index_handler_raises_forbidden_on_escape() -> None:
    """make_index_handler converts a sandbox escape into a Forbidden error."""
    handler = make_index_handler("/srv", MagicMock())
    request = HttpRequest("GET", "/", {}, b"")
    ctx = RequestContext(correlation_id=None, start_ns=0)

    with patch(
        "pyhttpd.application.handlers.files.resolve_sandbox_path",
        side_effect=ForbiddenPath(),
    ):
        with pytest.raises(Forbidden):
            handler(request, ctx)

"""Unit tests for transport layer logging events."""

import logging
import socket
from unittest.mock import MagicMock, patch

import pytest

from pyhttpd.adapters import ServerLifecycle
from pyhttpd.adapters.config import ServerConfig
from pyhttpd.adapters.transport import (
    ConnectionLimiter,
    WorkerContext,
    handle_client,
    run_server,
)
from pyhttpd.domain import ForbiddenPath, HttpRequest, RequestEntityTooLarge


@pytest.fixture(name="mock_socket")
def fixture_mock_socket():
    """Create a mock socket."""
    sock = MagicMock(spec=socket.socket)
    sock.recv.return_value = b""
    return sock


@pytest.fixture(name="mock_args")
def fixture_mock_args():
    """Create mock CLI arguments."""
    return MagicMock(
        host="localhost",
        port=8080,
        cert=None,
        key=None,
        max_connections=100,
        max_connections_per_ip=10,
        rate_limit=0,
        rate_window_ms=0,
        burst_capacity=0,
        rate_limit_dry_run=False,
        directory=".",
        cors_allowed_origins="*",
        cors_allowed_methods="GET,POST,OPTIONS",
        cors_allowed_headers="Content-Type",
        cors_expose_headers="X-Request-ID",
        cors_allow_credentials=False,
        cors_max_age=86400,
    )


@pytest.fixture(name="mock_config")
def fixture_mock_config():
    """Create mock ServerConfig."""
    return ServerConfig(socket_timeout=1, shutdown_grace_seconds=1)


@pytest.fixture(name="mock_lifecycle")
def fixture_mock_lifecycle():
    """Create mock ServerLifecycle."""
    lifecycle = MagicMock(spec=ServerLifecycle)
    lifecycle.should_stop.side_effect = [False, True]  # Run once then stop
    lifecycle.is_draining.return_value = False
    return lifecycle


def test_accept_loop_logs_server_listening(
    mock_args, mock_config, mock_lifecycle, caplog
):
    """Verify server_listening event is logged."""
    caplog.set_level(logging.INFO)

    server_socket = MagicMock()
    server_socket.accept.side_effect = OSError("Stop loop")  # Break loop
    connection_limiter = ConnectionLimiter(
        mock_args.max_connections, mock_args.max_connections_per_ip
    )
    handler_context = WorkerContext(directory=mock_args.directory)

    # We anticipate OSError log, so we filter for listening event specifically
    try:
        run_server(
            server_socket,
            mock_args,
            mock_config,
            mock_lifecycle,
            handler_context,
            connection_limiter,
        )
    except OSError:
        pass

    listening_record = next(
        (r for r in caplog.records if getattr(r, "event", None) == "server_listening"),
        None,
    )
    assert listening_record is not None
    assert listening_record.host == "localhost"
    assert listening_record.port == 8080


def test_accept_loop_logs_client_accepted(
    mock_args, mock_config, mock_lifecycle, caplog
):
    """Verify client_accepted event is logged at DEBUG level."""
    caplog.set_level(logging.DEBUG)

    # Enable DEBUG logging for the specific logger
    logging.getLogger("http_server.transport.accept").setLevel(logging.DEBUG)

    with patch("threading.Thread"):
        server_socket = MagicMock()
        # Accept one client, then raise OSError to break loop
        client_sock = MagicMock()
        server_socket.accept.side_effect = [
            (client_sock, ("127.0.0.1", 12345)),
            OSError("Stop loop"),
        ]
        connection_limiter = ConnectionLimiter(
            mock_args.max_connections, mock_args.max_connections_per_ip
        )
        handler_context = WorkerContext(directory=mock_args.directory)

        # Ensure loop breaks on error by overriding side_effect
        mock_lifecycle.should_stop.side_effect = None
        mock_lifecycle.should_stop.return_value = True

        run_server(
            server_socket,
            mock_args,
            mock_config,
            mock_lifecycle,
            handler_context,
            connection_limiter,
        )

    accepted_record = next(
        (r for r in caplog.records if getattr(r, "event", None) == "client_accepted"),
        None,
    )
    assert accepted_record is not None
    assert accepted_record.client == "127.0.0.1:12345"


def test_worker_logs_lifecycle_events(caplog):
    """Verify request_started, request_complete, socket_closed events."""
    # Set root http_server logger to DEBUG so all children (transport, io) log DEBUG
    logging.getLogger("http_server").setLevel(logging.DEBUG)
    caplog.set_level(logging.DEBUG)

    client_sock = MagicMock()
    # Simulate a valid request then close
    client_sock.recv.side_effect = [
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"",  # EOF
    ]

    context = MagicMock(spec=WorkerContext)
    context.directory = "."
    context.lifecycle = MagicMock()
    context.lifecycle.is_draining.return_value = False
    context.config = MagicMock()
    context.cors_config = None
    context.rate_limiter = None
    context.connection_limiter = None

    handle_client(client_sock, ("127.0.0.1", 54321), context)

    # Check for events (filter out logs without events, e.g. from IO logger)
    events = [
        getattr(r, "event", None) for r in caplog.records if getattr(r, "event", None)
    ]

    assert "request_started" in events
    assert "request_line_parsed" in events
    assert "request_complete" in events
    assert "socket_closed" in events

    # Verify correlation IDs match for the same request
    started = next(
        r for r in caplog.records if getattr(r, "event", None) == "request_started"
    )
    complete = next(
        r for r in caplog.records if getattr(r, "event", None) == "request_complete"
    )

    assert hasattr(started, "correlation_id")
    assert started.correlation_id != "-"
    assert started.correlation_id == complete.correlation_id


def test_worker_logs_body_size_exceeded(caplog):
    """Verify body_size_exceeded event."""
    logging.getLogger("http_server").setLevel(logging.WARNING)
    caplog.set_level(logging.WARNING)

    client_sock = MagicMock()

    with patch(
        "pyhttpd.adapters.transport.request_reader.receive_request"
    ) as mock_recv:
        mock_recv.side_effect = RequestEntityTooLarge("Too big")

        context = MagicMock(spec=WorkerContext)
        context.lifecycle = MagicMock()
        context.lifecycle.is_draining.return_value = False

        handle_client(client_sock, ("127.0.0.1", 54321), context)

    warning_record = next(
        (
            r
            for r in caplog.records
            if getattr(r, "event", None) == "body_size_exceeded"
        ),
        None,
    )

    assert warning_record is not None
    assert warning_record.client == "127.0.0.1:54321"


def _draining_context():
    """Build a WorkerContext mock whose lifecycle reports draining."""
    context = MagicMock(spec=WorkerContext)
    context.lifecycle = MagicMock()
    context.lifecycle.is_draining.return_value = True
    return context


def _idle_context():
    """Build a WorkerContext mock whose lifecycle is not draining."""
    context = MagicMock(spec=WorkerContext)
    context.lifecycle = MagicMock()
    context.lifecycle.is_draining.return_value = False
    return context


def test_worker_logs_forbidden_path(caplog):
    """Verify a ForbiddenPath yields a 403 response and forbidden_path warning."""
    logging.getLogger("http_server").setLevel(logging.WARNING)
    caplog.set_level(logging.WARNING)

    client_sock = MagicMock()

    with (
        patch("pyhttpd.adapters.transport.request_reader.receive_request") as mock_recv,
        patch("pyhttpd.adapters.transport.request_reader.send_response") as mock_send,
    ):
        mock_recv.side_effect = ForbiddenPath("escape attempt")

        handle_client(client_sock, ("127.0.0.1", 54321), _idle_context())

    warning_record = next(
        (r for r in caplog.records if getattr(r, "event", None) == "forbidden_path"),
        None,
    )
    assert warning_record is not None
    assert warning_record.client == "127.0.0.1:54321"

    sent_response = mock_send.call_args[0][1]
    assert sent_response.status_line == "HTTP/1.1 403 Forbidden"


def test_worker_logs_malformed_request(caplog):
    """Verify a ValueError yields a 400 response and malformed_request event."""
    logging.getLogger("http_server").setLevel(logging.WARNING)
    caplog.set_level(logging.WARNING)

    client_sock = MagicMock()

    with (
        patch("pyhttpd.adapters.transport.request_reader.receive_request") as mock_recv,
        patch("pyhttpd.adapters.transport.request_reader.send_response") as mock_send,
    ):
        mock_recv.side_effect = ValueError("bad request line")

        handle_client(client_sock, ("127.0.0.1", 54321), _idle_context())

    warning_record = next(
        (r for r in caplog.records if getattr(r, "event", None) == "malformed_request"),
        None,
    )
    assert warning_record is not None
    assert warning_record.client == "127.0.0.1:54321"

    sent_response = mock_send.call_args[0][1]
    assert sent_response.status_line.startswith("HTTP/1.1 400")


def test_worker_sends_draining_response_and_stops():
    """Verify a draining lifecycle sends the draining body and ends the loop."""
    client_sock = MagicMock()

    with (
        patch("pyhttpd.adapters.transport.request_reader.receive_request") as mock_recv,
        patch("pyhttpd.adapters.transport.worker_lifecycle.send_response") as mock_send,
    ):
        handle_client(client_sock, ("127.0.0.1", 54321), _draining_context())

    mock_recv.assert_not_called()

    sent_response = mock_send.call_args[0][1]
    assert sent_response.body == b"draining"
    assert sent_response.status_line == "HTTP/1.1 503 Service Unavailable"


def test_worker_logs_worker_error_and_sends_500(caplog):
    """Verify an unexpected handler error logs worker_error and sends a 500."""
    logging.getLogger("http_server").setLevel(logging.ERROR)
    caplog.set_level(logging.ERROR)

    client_sock = MagicMock()
    request = HttpRequest("GET", "/", {}, b"")

    def exploding_chain(_request, _ctx):
        raise RuntimeError("handler blew up")

    with (
        patch("pyhttpd.adapters.transport.request_reader.receive_request") as mock_recv,
        patch("pyhttpd.adapters.transport.worker.send_response") as mock_send,
        patch(
            "pyhttpd.adapters.transport.worker.build_worker_chain",
            return_value=exploding_chain,
        ),
    ):
        mock_recv.side_effect = [(request, b""), (None, b"")]

        context = _idle_context()
        context.cors_config = None
        context.rate_limiter = None
        context.connection_limiter = None
        context.directory = "."

        handle_client(client_sock, ("127.0.0.1", 54321), context)

    error_record = next(
        (r for r in caplog.records if getattr(r, "event", None) == "worker_error"),
        None,
    )
    assert error_record is not None
    assert error_record.client == "127.0.0.1:54321"

    sent_response = mock_send.call_args[0][1]
    assert sent_response.status_line == "HTTP/1.1 500 Internal Server Error"


def test_accept_loop_rejects_when_connection_limit_reached(
    mock_args, mock_config, mock_lifecycle, caplog
):
    """Verify a full connection limiter yields a 503, closes the socket, logs warning."""
    logging.getLogger("http_server").setLevel(logging.WARNING)
    caplog.set_level(logging.WARNING)

    client_sock = MagicMock()
    server_socket = MagicMock()
    server_socket.accept.side_effect = [
        (client_sock, ("127.0.0.1", 12345)),
        OSError("Stop loop"),
    ]
    mock_lifecycle.should_stop.side_effect = None
    mock_lifecycle.should_stop.return_value = True

    connection_limiter = ConnectionLimiter(max_connections=1, max_connections_per_ip=10)
    connection_limiter.acquire("10.0.0.1")
    handler_context = WorkerContext(directory=mock_args.directory)

    with (
        patch("threading.Thread") as mock_thread,
        patch("pyhttpd.adapters.transport.server.send_response") as mock_send,
    ):
        run_server(
            server_socket,
            mock_args,
            mock_config,
            mock_lifecycle,
            handler_context,
            connection_limiter,
        )

    mock_thread.assert_not_called()
    client_sock.close.assert_called_once()

    sent_response = mock_send.call_args[0][1]
    assert sent_response.status_line == "HTTP/1.1 503 Service Unavailable"

    warning_record = next(
        (
            r
            for r in caplog.records
            if getattr(r, "event", None) == "connection_limit_reached"
        ),
        None,
    )
    assert warning_record is not None
    assert warning_record.client == "127.0.0.1:12345"


def test_accept_loop_rejects_when_draining(mock_args, mock_config, mock_lifecycle):
    """Verify a draining server sends the draining body, closes socket, spawns nothing."""
    client_sock = MagicMock()
    server_socket = MagicMock()
    server_socket.accept.side_effect = [
        (client_sock, ("127.0.0.1", 12345)),
        OSError("Stop loop"),
    ]
    mock_lifecycle.should_stop.side_effect = None
    mock_lifecycle.should_stop.return_value = True
    mock_lifecycle.is_draining.return_value = True

    connection_limiter = ConnectionLimiter(
        mock_args.max_connections, mock_args.max_connections_per_ip
    )
    handler_context = WorkerContext(directory=mock_args.directory)

    with (
        patch("threading.Thread") as mock_thread,
        patch("pyhttpd.adapters.transport.server.send_response") as mock_send,
    ):
        run_server(
            server_socket,
            mock_args,
            mock_config,
            mock_lifecycle,
            handler_context,
            connection_limiter,
        )

    mock_thread.assert_not_called()
    client_sock.close.assert_called_once()

    sent_response = mock_send.call_args[0][1]
    assert sent_response.body == b"draining"

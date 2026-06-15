"""Unit tests for transport layer logging events."""

import logging
import socket
from unittest.mock import MagicMock, patch

import pytest

from pyhttpd.adapters.transport.connection_limiter import ConnectionLimiter
from pyhttpd.adapters.transport.server import run_server
from pyhttpd.bootstrap import ServerConfig
from pyhttpd.domain import RequestEntityTooLarge
from pyhttpd.lifecycle import ServerLifecycle
from pyhttpd.transport import WorkerContext, handle_client


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

    # Patch the function where it is USED (in worker.py namespace)
    with patch("pyhttpd.adapters.transport.worker.receive_request") as mock_recv:
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

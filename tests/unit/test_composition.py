"""Unit tests for the composition root wiring."""

import socket

from pyhttpd import composition
from pyhttpd.adapters.config import ServerConfig, parse_cli_args
from pyhttpd.adapters.ratelimit import TokenBucketLimiter
from pyhttpd.adapters.transport import ConnectionLimiter, WorkerContext
from pyhttpd.composition import (
    Server,
    _create_cors_config,
    _create_rate_limiter,
    _create_worker_context,
    build_server,
)
from pyhttpd.domain import CorsConfig


def _args(tmp_path, extra=None):
    """Build a parsed argument namespace bound to an ephemeral port."""
    argv = ["--directory", str(tmp_path), "--host", "127.0.0.1", "--port", "0"]
    if extra:
        argv.extend(extra)
    return parse_cli_args(argv)


def test_create_cors_config_splits_and_strips(tmp_path):
    """CORS origin lists are comma-split with surrounding whitespace removed."""
    args = _args(tmp_path, ["--cors-allowed-origins", "http://a.com , http://b.com"])
    cors = _create_cors_config(args)
    assert isinstance(cors, CorsConfig)
    assert cors.allowed_origins == ["http://a.com", "http://b.com"]


def test_create_cors_config_drops_empty_entries(tmp_path):
    """Empty comma segments are filtered out of CORS lists."""
    args = _args(tmp_path, ["--cors-allowed-methods", "GET, ,POST"])
    assert _create_cors_config(args).allowed_methods == ["GET", "POST"]


def test_create_rate_limiter_enabled(tmp_path):
    """A positive rate limit and window produce a token-bucket limiter."""
    args = _args(tmp_path, ["--rate-limit", "5", "--rate-window-ms", "1000"])
    assert isinstance(_create_rate_limiter(args), TokenBucketLimiter)


def test_create_rate_limiter_disabled_when_rate_zero(tmp_path):
    """A zero rate limit disables rate limiting."""
    assert _create_rate_limiter(_args(tmp_path, ["--rate-limit", "0"])) is None


def test_create_rate_limiter_disabled_when_window_zero(tmp_path):
    """A zero window disables rate limiting."""
    args = _args(tmp_path, ["--rate-limit", "5", "--rate-window-ms", "0"])
    assert _create_rate_limiter(args) is None


def test_create_worker_context_wires_collaborators(tmp_path):
    """The worker context carries directory, limiter, and CORS config."""
    args = _args(tmp_path)
    config = ServerConfig(socket_timeout=1, shutdown_grace_seconds=1)
    limiter = ConnectionLimiter(args.max_connections, args.max_connections_per_ip)

    class _Lifecycle:
        """Minimal draining-state stand-in."""

        def is_draining(self):
            """Report not draining."""
            return False

        def should_stop(self):
            """Report no stop requested."""
            return False

        def wait_for_workers(self, _timeout):
            """Report workers joined."""
            return True

    context = _create_worker_context(args, config, _Lifecycle(), limiter)
    assert isinstance(context, WorkerContext)
    assert context.directory == str(tmp_path)
    assert context.connection_limiter is limiter
    assert isinstance(context.cors_config, CorsConfig)


def test_server_serve_delegates_to_run_server(monkeypatch, tmp_path):
    """Server.serve forwards the wired collaborators to run_server."""
    captured = {}

    def _fake_run_server(*passed):
        captured["call"] = passed

    monkeypatch.setattr(composition, "run_server", _fake_run_server)
    sentinel_socket = object()
    handler_context = object()
    server = Server(
        server_socket=sentinel_socket,
        args=_args(tmp_path),
        config=ServerConfig(socket_timeout=1, shutdown_grace_seconds=1),
        lifecycle=object(),
        handler_context=handler_context,
        connection_limiter=object(),
    )
    server.serve()
    assert captured["call"][0] is sentinel_socket
    assert captured["call"][4] is handler_context


def test_build_server_binds_and_wires(monkeypatch, tmp_path):
    """build_server configures runtime and returns a fully wired Server."""
    monkeypatch.setattr(composition, "configure_logging", lambda *a, **k: None)
    monkeypatch.setattr(composition.signal, "signal", lambda *a, **k: None)
    server = build_server(_args(tmp_path))
    try:
        assert isinstance(server, Server)
        assert isinstance(server.server_socket, socket.socket)
        assert isinstance(server.handler_context, WorkerContext)
        assert isinstance(server.connection_limiter, ConnectionLimiter)
        assert server.handler_context.directory == str(tmp_path)
    finally:
        server.server_socket.close()

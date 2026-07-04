"""Unit tests for the composition root wiring."""

import hashlib
import socket

import pytest

from pyhttpd import composition
from pyhttpd.adapters.auth import ApiKeyAuthenticator, JwtAuthenticator
from pyhttpd.adapters.config import ServerConfig, parse_cli_args
from pyhttpd.adapters.ratelimit import TokenBucketLimiter
from pyhttpd.adapters.transport import ConnectionLimiter, WorkerContext
from pyhttpd.composition import Server, build_server
from pyhttpd.domain import CorsConfig


def _args(tmp_path, extra=None):
    """Build a parsed argument namespace bound to an ephemeral port."""
    argv = ["--directory", str(tmp_path), "--host", "127.0.0.1", "--port", "0"]
    if extra:
        argv.extend(extra)
    return parse_cli_args(argv)


@pytest.fixture
def build(monkeypatch):
    """Yield a builder that wires a real Server and closes its socket on teardown."""
    monkeypatch.setattr(composition, "configure_logging", lambda *a, **k: None)
    monkeypatch.setattr(composition.signal, "signal", lambda *a, **k: None)
    built: list[Server] = []

    def _build(tmp_path, extra=None) -> Server:
        server = build_server(_args(tmp_path, extra))
        built.append(server)
        return server

    yield _build
    for server in built:
        server.server_socket.close()


def test_cors_origins_split_and_stripped(build, tmp_path):
    """CORS origin lists are comma-split with surrounding whitespace removed."""
    context = build(
        tmp_path, ["--cors-allowed-origins", "http://a.com , http://b.com"]
    ).handler_context
    assert context.cors_config.allowed_origins == ["http://a.com", "http://b.com"]


def test_cors_methods_drop_empty_entries(build, tmp_path):
    """Empty comma segments are filtered out of CORS lists."""
    context = build(tmp_path, ["--cors-allowed-methods", "GET, ,POST"]).handler_context
    assert context.cors_config.allowed_methods == ["GET", "POST"]


def test_rate_limiter_enabled(build, tmp_path):
    """A positive rate limit and window produce a token-bucket limiter."""
    context = build(
        tmp_path, ["--rate-limit", "5", "--rate-window-ms", "1000"]
    ).handler_context
    assert isinstance(context.rate_limiter, TokenBucketLimiter)


def test_rate_limiter_disabled_when_rate_zero(build, tmp_path):
    """A zero rate limit disables rate limiting."""
    assert build(tmp_path, ["--rate-limit", "0"]).handler_context.rate_limiter is None


def test_rate_limiter_disabled_when_window_zero(build, tmp_path):
    """A zero window disables rate limiting."""
    context = build(
        tmp_path, ["--rate-limit", "5", "--rate-window-ms", "0"]
    ).handler_context
    assert context.rate_limiter is None


def test_auth_credentials_and_roles_drive_authentication(build, tmp_path):
    """Comma-split credentials and pipe-split roles authenticate real API keys."""
    reader_key, writer_key = "reader-key", "writer-key"
    reader_hash = hashlib.sha256(reader_key.encode()).hexdigest()
    writer_hash = hashlib.sha256(writer_key.encode()).hexdigest()
    context = build(
        tmp_path,
        [
            "--auth-mode",
            "api-key",
            "--auth-credentials",
            f"reader:{reader_hash}, writer:{writer_hash}",
            "--auth-roles",
            "reader:files:read, writer:files:read|files:write",
        ],
    ).handler_context

    reader = context.authenticator.authenticate(
        {"authorization": f"ApiKey {reader_key}"}
    )
    writer = context.authenticator.authenticate(
        {"authorization": f"ApiKey {writer_key}"}
    )

    assert reader is not None and reader.identity == "reader"
    assert reader.scopes == frozenset({"files:read"})
    assert writer is not None and writer.identity == "writer"
    assert writer.scopes == frozenset({"files:read", "files:write"})


def test_authenticator_disabled_by_default(build, tmp_path):
    """With auth mode none the composition root builds no authenticator."""
    assert build(tmp_path).handler_context.authenticator is None


def test_authenticator_api_key_mode(build, tmp_path):
    """Api-key mode threads an ApiKeyAuthenticator into the worker context."""
    context = build(
        tmp_path, ["--auth-mode", "api-key", "--auth-credentials", "reader:deadbeef"]
    ).handler_context
    assert isinstance(context.authenticator, ApiKeyAuthenticator)


def test_authenticator_jwt_mode(build, tmp_path):
    """JWT mode threads a JwtAuthenticator into the worker context."""
    context = build(
        tmp_path, ["--auth-mode", "jwt", "--jwt-secret", "s"]
    ).handler_context
    assert isinstance(context.authenticator, JwtAuthenticator)


def test_worker_context_wires_collaborators(build, tmp_path):
    """The worker context carries directory, the shared limiter, and CORS config."""
    server = build(tmp_path)
    context = server.handler_context
    assert isinstance(context, WorkerContext)
    assert context.directory == str(tmp_path)
    assert context.connection_limiter is server.connection_limiter
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

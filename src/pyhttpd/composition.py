"""Composition root wiring transport collaborators across layers."""

import argparse
import logging
import signal
import socket
from dataclasses import dataclass
from typing import Optional

from pyhttpd.adapters.auth import (
    ApiKeyAuthenticator,
    BasicAuthenticator,
    JwtAuthenticator,
)
from pyhttpd.adapters.config.cli_args import ServerConfig
from pyhttpd.adapters.lifecycle import ServerLifecycle
from pyhttpd.adapters.logging.setup import configure_logging
from pyhttpd.adapters.metrics import LockingMetricsSink
from pyhttpd.adapters.ratelimit.token_bucket import TokenBucketLimiter
from pyhttpd.adapters.session import InMemorySessionStore
from pyhttpd.adapters.tls import create_server_socket
from pyhttpd.adapters.transport.connection_limiter import ConnectionLimiter
from pyhttpd.adapters.transport.context import WorkerContext
from pyhttpd.adapters.transport.server import run_server
from pyhttpd.application.config_validation import validate_startup_config
from pyhttpd.application.middleware.session import SessionCookiePolicy
from pyhttpd.domain import (
    AuthConfig,
    Authenticator,
    CorsConfig,
    FileServingOptions,
    LifecycleState,
    MetricsSink,
    PhaseTimeouts,
    TokenBucketSettings,
)
from pyhttpd.domain.proxy import ProxyTarget, parse_proxy_pass

MAIN_LOGGER = logging.getLogger("http_server.main")


def _create_cors_config(args: argparse.Namespace) -> CorsConfig:
    """Create CORS configuration from CLI arguments."""
    return CorsConfig(
        allowed_origins=[
            o.strip() for o in args.cors_allowed_origins.split(",") if o.strip()
        ],
        allowed_methods=[
            m.strip() for m in args.cors_allowed_methods.split(",") if m.strip()
        ],
        allowed_headers=[
            h.strip() for h in args.cors_allowed_headers.split(",") if h.strip()
        ],
        expose_headers=[
            h.strip() for h in args.cors_expose_headers.split(",") if h.strip()
        ],
        allow_credentials=args.cors_allow_credentials,
        max_age=args.cors_max_age,
    )


def _parse_pairs(raw: str) -> dict[str, str]:
    """Parse a comma list of identity:value pairs into a mapping."""
    pairs: dict[str, str] = {}
    for entry in raw.split(","):
        identity, separator, value = entry.strip().partition(":")
        if identity and separator:
            pairs[identity] = value
    return pairs


def _create_auth_config(args: argparse.Namespace) -> AuthConfig:
    """Create authentication configuration from CLI arguments."""
    roles = {
        identity: [scope for scope in spec.split("|") if scope]
        for identity, spec in _parse_pairs(args.auth_roles).items()
    }
    return AuthConfig(
        mode=args.auth_mode,
        credentials=_parse_pairs(args.auth_credentials),
        roles=roles,
        jwt_secret=args.jwt_secret,
        jwt_issuer=args.jwt_issuer or None,
        jwt_audience=args.jwt_audience or None,
    )


def _create_authenticator(args: argparse.Namespace) -> Optional[Authenticator]:
    """Create the configured authenticator, or None when auth is disabled."""
    if args.auth_mode == "none":
        return None
    config = _create_auth_config(args)
    if args.auth_mode == "jwt":
        return JwtAuthenticator(config)
    if args.auth_mode == "basic":
        return BasicAuthenticator(config)
    return ApiKeyAuthenticator(config)


def _create_rate_limiter(args: argparse.Namespace) -> Optional[TokenBucketLimiter]:
    """Create rate limiter if configured."""
    if args.rate_limit > 0 and args.rate_window_ms > 0:
        return TokenBucketLimiter(
            TokenBucketSettings(
                rate_limit=args.rate_limit,
                window_ms=args.rate_window_ms,
                burst_capacity=args.burst_capacity,
                dry_run=args.rate_limit_dry_run,
            )
        )
    return None


def _create_metrics_sink(args: argparse.Namespace) -> Optional[MetricsSink]:
    """Create the metrics sink when metrics are enabled, else None."""
    return LockingMetricsSink() if args.metrics else None


def _create_file_options(args: argparse.Namespace) -> FileServingOptions:
    """Create static file serving options from CLI arguments."""
    return FileServingOptions(
        cache_control=args.file_cache_control,
        gzip=args.file_gzip,
        gzip_min_bytes=args.file_gzip_min_bytes,
        content_sniffing=args.content_sniffing,
    )


def _create_session_store(
    args: argparse.Namespace,
) -> Optional[InMemorySessionStore]:
    """Create the session store when a session secret is configured."""
    if not args.session_secret:
        return None
    return InMemorySessionStore(ttl_seconds=args.session_ttl)


def _create_session_policy(
    args: argparse.Namespace,
) -> Optional[SessionCookiePolicy]:
    """Create the session cookie policy when sessions are enabled."""
    if not args.session_secret:
        return None
    return SessionCookiePolicy(
        secret=args.session_secret,
        ttl_seconds=args.session_ttl,
        secure=args.session_cookie_secure,
        same_site=args.session_cookie_samesite,
    )


def _create_proxy_targets(args: argparse.Namespace) -> tuple[ProxyTarget, ...]:
    """Parse --proxy-pass specs, enforcing the upstream-host allowlist."""
    specs = args.proxy_pass or []
    if not specs:
        return ()
    allowlist = set(args.proxy_allow_host or [])
    targets = []
    for spec in specs:
        try:
            target = parse_proxy_pass(spec)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        if target.host not in allowlist:
            raise SystemExit(
                f"proxy upstream host not allowlisted: {target.host} "
                f"(add --proxy-allow-host {target.host})"
            )
        targets.append(target)
    return tuple(targets)


def _create_phase_timeouts(args: argparse.Namespace) -> PhaseTimeouts:
    """Create per-phase request timeouts from CLI arguments."""
    return PhaseTimeouts(
        header_read_seconds=args.header_read_timeout,
        body_read_seconds=args.body_read_timeout,
        handler_seconds=args.handler_timeout,
    )


def _create_worker_context(
    args: argparse.Namespace,
    config: ServerConfig,
    lifecycle: LifecycleState,
    connection_limiter: ConnectionLimiter,
    metrics_sink: Optional[MetricsSink] = None,
) -> WorkerContext:
    return WorkerContext(
        directory=args.directory,
        connection_limiter=connection_limiter,
        rate_limiter=_create_rate_limiter(args),
        lifecycle=lifecycle,
        config=config,
        cors_config=_create_cors_config(args),
        authenticator=_create_authenticator(args),
        metrics_sink=metrics_sink,
        file_options=_create_file_options(args),
        phase_timeouts=_create_phase_timeouts(args),
        error_format=args.error_format,
        allow_chunked_requests=args.allow_chunked_requests,
        expect_continue=args.expect_continue,
        session_store=_create_session_store(args),
        session_policy=_create_session_policy(args),
        enable_sse=args.enable_sse,
        enable_websocket=args.enable_websocket,
        proxy_targets=_create_proxy_targets(args),
        proxy_timeout=args.proxy_timeout,
    )


@dataclass
class Server:
    """Fully wired server ready to accept connections."""

    server_socket: socket.socket
    args: argparse.Namespace
    config: ServerConfig
    lifecycle: LifecycleState
    handler_context: WorkerContext
    connection_limiter: ConnectionLimiter

    def serve(self) -> None:
        """Run the accept loop on the listening socket."""
        run_server(
            self.server_socket,
            self.args,
            self.config,
            self.lifecycle,
            self.handler_context,
            self.connection_limiter,
        )


def build_server(args: argparse.Namespace) -> Server:
    """Configure runtime, register signals, and wire the server collaborators."""
    configure_logging(args.log_level, args.log_destination)

    config_errors = validate_startup_config(args)
    if config_errors:
        for message in config_errors:
            MAIN_LOGGER.critical(
                "Invalid configuration",
                extra={"event": "config_invalid", "error_type": message},
            )
        raise SystemExit(f"Invalid configuration: {'; '.join(config_errors)}")

    config = ServerConfig(
        socket_timeout=args.socket_timeout,
        shutdown_grace_seconds=args.shutdown_grace_seconds,
    )
    lifecycle = ServerLifecycle()

    def shutdown_handler(signum: int, _frame) -> None:
        MAIN_LOGGER.info(
            "Shutdown signal received",
            extra={"event": "shutdown_signal_received", "signal": signum},
        )
        lifecycle.begin_draining()

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    MAIN_LOGGER.info(
        "HTTP server starting",
        extra={
            "event": "server_starting",
            "host": args.host,
            "port": args.port,
            "directory": args.directory,
            "log_destination": args.log_destination,
            "log_level": args.log_level,
            "tls": bool(args.cert and args.key),
            "socket_timeout": config.socket_timeout,
            "shutdown_grace_seconds": config.shutdown_grace_seconds,
            "auth_mode": args.auth_mode,
            "metrics": args.metrics,
        },
    )

    server_socket = create_server_socket(args)
    connection_limiter = ConnectionLimiter(
        args.max_connections,
        args.max_connections_per_ip,
    )
    metrics_sink = _create_metrics_sink(args)
    handler_context = _create_worker_context(
        args, config, lifecycle, connection_limiter, metrics_sink
    )
    return Server(
        server_socket=server_socket,
        args=args,
        config=config,
        lifecycle=lifecycle,
        handler_context=handler_context,
        connection_limiter=connection_limiter,
    )

"""Configuration-to-collaborator factories for the composition root.

Holds the ``_create_*`` factories that translate parsed CLI/config arguments
into wired collaborators (authenticators, limiters, session store, proxy
targets, the worker context) plus the SIGHUP reload registration, keeping that
breadth of imports out of the thin ``composition`` orchestration module.
"""

import argparse
import logging
import signal
import tomllib
from typing import Optional

from pyhttpd.adapters.auth import (
    ApiKeyAuthenticator,
    BasicAuthenticator,
    JwtAuthenticator,
)
from pyhttpd.adapters.auth.client_cert import ClientCertAuthenticator
from pyhttpd.adapters.config.cli_args import ServerConfig
from pyhttpd.adapters.config.file_config import load_config_file, reapply_overlay
from pyhttpd.adapters.logging.access_log import AccessLogger
from pyhttpd.adapters.metrics import LockingMetricsSink
from pyhttpd.adapters.ratelimit.token_bucket import TokenBucketLimiter
from pyhttpd.adapters.session import InMemorySessionStore
from pyhttpd.adapters.transport.connection_limiter import ConnectionLimiter
from pyhttpd.adapters.transport.context import WorkerContext
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

WIRING_LOGGER = logging.getLogger("http_server.main")


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
    if args.auth_mode == "client-cert":
        return ClientCertAuthenticator(config)
    return ApiKeyAuthenticator(config)


def _create_client_cert_roles(args: argparse.Namespace) -> Optional[dict[str, list]]:
    """Build the cert-identity-to-scope map for mutual-TLS authentication."""
    if args.auth_mode != "client-cert":
        return None
    return {
        identity: [scope for scope in spec.split("|") if scope]
        for identity, spec in _parse_pairs(args.auth_roles).items()
    }


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


def _create_access_logger(args: argparse.Namespace) -> Optional[AccessLogger]:
    """Create the Combined Log Format access logger, or None when disabled."""
    destination = args.access_log
    if destination == "off":
        return None
    logger = logging.getLogger("pyhttpd.access")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
    handler: logging.Handler = (
        logging.StreamHandler()
        if destination == "stdout"
        else logging.FileHandler(destination)
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return AccessLogger(logger)


def _create_file_options(args: argparse.Namespace) -> FileServingOptions:
    """Create static file serving options from CLI arguments."""
    return FileServingOptions(
        cache_control=args.file_cache_control,
        gzip=args.file_gzip,
        gzip_min_bytes=args.file_gzip_min_bytes,
        content_sniffing=args.content_sniffing,
        autoindex=args.autoindex,
    )


def _create_session_store(args: argparse.Namespace) -> Optional[InMemorySessionStore]:
    """Create the session store when a session secret is configured."""
    if not args.session_secret:
        return None
    return InMemorySessionStore(ttl_seconds=args.session_ttl)


def _create_session_policy(args: argparse.Namespace) -> Optional[SessionCookiePolicy]:
    """Create the session cookie policy when sessions are enabled."""
    if not args.session_secret:
        return None
    return SessionCookiePolicy(
        secret=args.session_secret,
        ttl_seconds=args.session_ttl,
        secure=args.session_cookie_secure,
        same_site=args.session_cookie_samesite,
    )


def _create_vhost_directories(args: argparse.Namespace) -> Optional[dict[str, str]]:
    """Parse --vhost host=dir specs into a host-to-directory mapping."""
    specs = args.vhost or []
    if not specs:
        return None
    mapping: dict[str, str] = {}
    for spec in specs:
        host, separator, directory = spec.partition("=")
        if not separator or not host.strip() or not directory.strip():
            raise SystemExit(f"invalid --vhost spec: {spec!r}")
        mapping[host.strip()] = directory.strip()
    return mapping


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
    """Assemble the shared worker context from parsed arguments."""
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
        vhost_directories=_create_vhost_directories(args),
        access_logger=_create_access_logger(args),
        client_cert_roles=_create_client_cert_roles(args),
    )


def _apply_reloadable_config(context: WorkerContext, args: argparse.Namespace) -> None:
    """Swap the SIGHUP-reloadable fields on the shared worker context."""
    context.error_format = args.error_format
    context.cors_config = _create_cors_config(args)
    context.file_options = _create_file_options(args)
    context.rate_limiter = _create_rate_limiter(args)
    context.allow_chunked_requests = args.allow_chunked_requests
    context.expect_continue = args.expect_continue


def register_config_reload(
    args: argparse.Namespace, handler_context: WorkerContext
) -> None:
    """On SIGHUP, re-read the config file and swap the reloadable fields."""
    if not args.config or not hasattr(signal, "SIGHUP"):
        return

    def reload_handler(signum: int, _frame) -> None:
        try:
            overlay = load_config_file(args.config)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            WIRING_LOGGER.error(
                "Config reload failed",
                extra={
                    "event": "config_reload_failed",
                    "error_type": type(exc).__name__,
                },
            )
            return
        reapply_overlay(args, overlay)
        _apply_reloadable_config(handler_context, args)
        WIRING_LOGGER.info(
            "Configuration reloaded",
            extra={"event": "config_reloaded", "signal": signum},
        )

    signal.signal(signal.SIGHUP, reload_handler)

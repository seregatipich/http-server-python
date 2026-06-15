"""Composition root wiring transport collaborators across layers."""

import argparse
from dataclasses import dataclass
from typing import Optional

from pyhttpd.adapters.config.cli_args import ServerConfig
from pyhttpd.adapters.ratelimit.token_bucket import TokenBucketLimiter
from pyhttpd.adapters.tls import create_server_socket
from pyhttpd.adapters.transport.connection_limiter import ConnectionLimiter
from pyhttpd.adapters.transport.context import WorkerContext
from pyhttpd.adapters.transport.server import run_server
from pyhttpd.domain import CorsConfig, LifecycleState, TokenBucketSettings


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


def _create_worker_context(
    args: argparse.Namespace,
    config: ServerConfig,
    lifecycle: LifecycleState,
    connection_limiter: ConnectionLimiter,
) -> WorkerContext:
    return WorkerContext(
        directory=args.directory,
        connection_limiter=connection_limiter,
        rate_limiter=_create_rate_limiter(args),
        lifecycle=lifecycle,
        config=config,
        cors_config=_create_cors_config(args),
    )


@dataclass
class Server:
    """Fully wired server ready to accept connections."""

    server_socket: object
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


def build_server(
    args: argparse.Namespace, config: ServerConfig, lifecycle: LifecycleState
) -> Server:
    """Build and wire the server and its transport collaborators."""
    server_socket = create_server_socket(args)
    connection_limiter = ConnectionLimiter(
        args.max_connections,
        args.max_connections_per_ip,
    )
    handler_context = _create_worker_context(
        args, config, lifecycle, connection_limiter
    )
    return Server(
        server_socket=server_socket,
        args=args,
        config=config,
        lifecycle=lifecycle,
        handler_context=handler_context,
        connection_limiter=connection_limiter,
    )

"""Backward-compatible re-exports for the relocated config adapter."""

from pyhttpd.adapters.config.cli_args import (
    DEFAULT_BURST_CAPACITY,
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_CONNECTIONS_PER_IP,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RATE_LIMIT_DRY_RUN,
    DEFAULT_RATE_WINDOW_MS,
    MAX_BODY_BYTES,
    ServerConfig,
    parse_cli_args,
)

__all__ = [
    "DEFAULT_BURST_CAPACITY",
    "DEFAULT_MAX_CONNECTIONS",
    "DEFAULT_MAX_CONNECTIONS_PER_IP",
    "DEFAULT_RATE_LIMIT",
    "DEFAULT_RATE_LIMIT_DRY_RUN",
    "DEFAULT_RATE_WINDOW_MS",
    "MAX_BODY_BYTES",
    "ServerConfig",
    "parse_cli_args",
]

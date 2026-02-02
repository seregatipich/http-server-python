"""Server configuration and CLI argument parsing."""

import argparse
import os
from dataclasses import dataclass


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value is not None else default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


MAX_BODY_BYTES = _env_int("HTTP_SERVER_MAX_BODY_BYTES", 5 * 1024 * 1024)
DEFAULT_MAX_CONNECTIONS = _env_int("HTTP_SERVER_MAX_CONNECTIONS", 200)
DEFAULT_MAX_CONNECTIONS_PER_IP = _env_int("HTTP_SERVER_MAX_CONNECTIONS_PER_IP", 20)
DEFAULT_RATE_LIMIT = _env_int("HTTP_SERVER_RATE_LIMIT", 50)
DEFAULT_RATE_WINDOW_MS = _env_int("HTTP_SERVER_RATE_WINDOW_MS", 10_000)
DEFAULT_BURST_CAPACITY = _env_int("HTTP_SERVER_BURST_CAPACITY", 25)
DEFAULT_RATE_LIMIT_DRY_RUN = _env_bool("HTTP_SERVER_RATE_LIMIT_DRY_RUN", False)
DEFAULT_SOCKET_TIMEOUT = _env_int("HTTP_SERVER_SOCKET_TIMEOUT", 60)
DEFAULT_SHUTDOWN_GRACE_SECONDS = _env_int("HTTP_SERVER_SHUTDOWN_GRACE_SECONDS", 30)
DEFAULT_CORS_ALLOWED_ORIGINS = _env_list("HTTP_SERVER_CORS_ALLOWED_ORIGINS", ["*"])
DEFAULT_CORS_ALLOWED_METHODS = _env_list(
    "HTTP_SERVER_CORS_ALLOWED_METHODS", ["GET", "POST", "OPTIONS"]
)
DEFAULT_CORS_ALLOWED_HEADERS = _env_list(
    "HTTP_SERVER_CORS_ALLOWED_HEADERS", ["Content-Type", "Authorization"]
)
DEFAULT_CORS_EXPOSE_HEADERS = _env_list(
    "HTTP_SERVER_CORS_EXPOSE_HEADERS", ["X-Request-ID"]
)
DEFAULT_CORS_ALLOW_CREDENTIALS = _env_bool("HTTP_SERVER_CORS_ALLOW_CREDENTIALS", False)
DEFAULT_CORS_MAX_AGE = _env_int("HTTP_SERVER_CORS_MAX_AGE", 86400)

HEADER_DELIMITER = b"\r\n\r\n"
FILES_ENDPOINT_PREFIX = "/files/"
ALLOWED_METHODS = {"GET", "POST", "OPTIONS"}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
}


@dataclass
class ServerConfig:
    """Server configuration including timeouts and shutdown settings."""

    socket_timeout: int
    shutdown_grace_seconds: int


def parse_cli_args(argv: list[str]) -> argparse.Namespace:
    """Return parsed CLI arguments for server configuration."""
    parser = argparse.ArgumentParser(description="HTTP server configuration")
    parser.add_argument("--directory", default=".")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=4221)
    parser.add_argument("--cert", help="Path to TLS certificate file")
    parser.add_argument("--key", help="Path to TLS private key file")
    default_log_level = os.getenv("HTTP_SERVER_LOG_LEVEL", "INFO").upper()
    default_destination = os.getenv("HTTP_SERVER_LOG_DESTINATION", "stdout")
    parser.add_argument(
        "--log-level",
        default=default_log_level,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        type=str.upper,
    )
    parser.add_argument(
        "--log-destination",
        default=default_destination,
        help="stdout or a file path",
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=DEFAULT_MAX_CONNECTIONS,
        help="Maximum concurrent connections (0 for unlimited)",
    )
    parser.add_argument(
        "--max-connections-per-ip",
        type=int,
        default=DEFAULT_MAX_CONNECTIONS_PER_IP,
        help="Maximum concurrent connections per client IP (0 for unlimited)",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=DEFAULT_RATE_LIMIT,
        help="Requests allowed per rate window (0 to disable)",
    )
    parser.add_argument(
        "--rate-window-ms",
        type=int,
        default=DEFAULT_RATE_WINDOW_MS,
        help="Rate limit window in milliseconds",
    )
    parser.add_argument(
        "--burst-capacity",
        type=int,
        default=DEFAULT_BURST_CAPACITY,
        help="Token bucket capacity for bursts",
    )
    parser.add_argument(
        "--rate-limit-dry-run",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_RATE_LIMIT_DRY_RUN,
        help="Log rate limit breaches without enforcing",
    )
    parser.add_argument(
        "--socket-timeout",
        type=int,
        default=DEFAULT_SOCKET_TIMEOUT,
        help="Socket timeout in seconds for request processing",
    )
    parser.add_argument(
        "--shutdown-grace-seconds",
        type=int,
        default=DEFAULT_SHUTDOWN_GRACE_SECONDS,
        help="Grace period in seconds for graceful shutdown",
    )
    parser.add_argument(
        "--cors-allowed-origins",
        default=",".join(DEFAULT_CORS_ALLOWED_ORIGINS),
        help="Comma-separated list of allowed CORS origins (default: *)",
    )
    parser.add_argument(
        "--cors-allowed-methods",
        default=",".join(DEFAULT_CORS_ALLOWED_METHODS),
        help="Comma-separated list of allowed CORS methods",
    )
    parser.add_argument(
        "--cors-allowed-headers",
        default=",".join(DEFAULT_CORS_ALLOWED_HEADERS),
        help="Comma-separated list of allowed CORS headers",
    )
    parser.add_argument(
        "--cors-expose-headers",
        default=",".join(DEFAULT_CORS_EXPOSE_HEADERS),
        help="Comma-separated list of exposed CORS headers",
    )
    parser.add_argument(
        "--cors-allow-credentials",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_CORS_ALLOW_CREDENTIALS,
        help="Allow credentials in CORS requests",
    )
    parser.add_argument(
        "--cors-max-age",
        type=int,
        default=DEFAULT_CORS_MAX_AGE,
        help="CORS preflight cache duration in seconds",
    )
    return parser.parse_args(argv)

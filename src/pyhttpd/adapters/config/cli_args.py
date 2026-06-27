"""Server configuration and CLI argument parsing."""

import argparse
import os
from dataclasses import dataclass

from pyhttpd.adapters.config.env import _env_bool, _env_int, _env_list, _env_str
from pyhttpd.domain import DEFAULT_AUTH_MODE, DEFAULT_MAX_BODY_BYTES

MAX_BODY_BYTES = _env_int("HTTP_SERVER_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)
DEFAULT_MAX_CONNECTIONS = _env_int("HTTP_SERVER_MAX_CONNECTIONS", 200)
DEFAULT_MAX_CONNECTIONS_PER_IP = _env_int("HTTP_SERVER_MAX_CONNECTIONS_PER_IP", 20)
DEFAULT_RATE_LIMIT = _env_int("HTTP_SERVER_RATE_LIMIT", 50)
DEFAULT_RATE_WINDOW_MS = _env_int("HTTP_SERVER_RATE_WINDOW_MS", 10_000)
DEFAULT_BURST_CAPACITY = _env_int("HTTP_SERVER_BURST_CAPACITY", 25)
DEFAULT_RATE_LIMIT_DRY_RUN = _env_bool("HTTP_SERVER_RATE_LIMIT_DRY_RUN", False)
DEFAULT_SOCKET_TIMEOUT = _env_int("HTTP_SERVER_SOCKET_TIMEOUT", 60)
DEFAULT_SHUTDOWN_GRACE_SECONDS = _env_int("HTTP_SERVER_SHUTDOWN_GRACE_SECONDS", 30)
DEFAULT_HEADER_READ_TIMEOUT = _env_int(
    "HTTP_SERVER_HEADER_READ_TIMEOUT", DEFAULT_SOCKET_TIMEOUT
)
DEFAULT_BODY_READ_TIMEOUT = _env_int(
    "HTTP_SERVER_BODY_READ_TIMEOUT", DEFAULT_SOCKET_TIMEOUT
)
DEFAULT_HANDLER_TIMEOUT = _env_int(
    "HTTP_SERVER_HANDLER_TIMEOUT", DEFAULT_SOCKET_TIMEOUT
)
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
DEFAULT_AUTH_MODE = _env_str("HTTP_SERVER_AUTH_MODE", DEFAULT_AUTH_MODE)
DEFAULT_AUTH_CREDENTIALS = _env_str("HTTP_SERVER_AUTH_CREDENTIALS", "")
DEFAULT_AUTH_ROLES = _env_str("HTTP_SERVER_AUTH_ROLES", "")
DEFAULT_JWT_SECRET = _env_str("HTTP_SERVER_JWT_SECRET", "")
DEFAULT_JWT_ISSUER = _env_str("HTTP_SERVER_JWT_ISSUER", "")
DEFAULT_JWT_AUDIENCE = _env_str("HTTP_SERVER_JWT_AUDIENCE", "")
DEFAULT_METRICS_ENABLED = _env_bool("HTTP_SERVER_METRICS", False)
DEFAULT_ENABLE_SSE = _env_bool("HTTP_SERVER_ENABLE_SSE", False)
DEFAULT_ENABLE_WEBSOCKET = _env_bool("HTTP_SERVER_ENABLE_WEBSOCKET", False)
DEFAULT_FILE_CACHE_CONTROL = _env_str("HTTP_SERVER_FILE_CACHE_CONTROL", "")
DEFAULT_FILE_GZIP = _env_bool("HTTP_SERVER_FILE_GZIP", False)
DEFAULT_FILE_GZIP_MIN_BYTES = _env_int("HTTP_SERVER_FILE_GZIP_MIN_BYTES", 1024)
DEFAULT_CONTENT_SNIFFING = _env_bool("HTTP_SERVER_CONTENT_SNIFFING", False)
DEFAULT_ERROR_FORMAT = _env_str("HTTP_SERVER_ERROR_FORMAT", "text")
DEFAULT_ALLOW_CHUNKED_REQUESTS = _env_bool("HTTP_SERVER_ALLOW_CHUNKED_REQUESTS", False)
DEFAULT_EXPECT_CONTINUE = _env_bool("HTTP_SERVER_EXPECT_CONTINUE", False)
DEFAULT_SESSION_SECRET = _env_str("HTTP_SERVER_SESSION_SECRET", "")
DEFAULT_SESSION_TTL = _env_int("HTTP_SERVER_SESSION_TTL", 3600)
DEFAULT_SESSION_COOKIE_SECURE = _env_bool("HTTP_SERVER_SESSION_COOKIE_SECURE", False)
DEFAULT_SESSION_COOKIE_SAMESITE = _env_str("HTTP_SERVER_SESSION_COOKIE_SAMESITE", "Lax")


@dataclass
class ServerConfig:
    """Server configuration including timeouts and shutdown settings."""

    socket_timeout: int
    shutdown_grace_seconds: int
    max_body_bytes: int = MAX_BODY_BYTES


def _add_logging_args(parser: argparse.ArgumentParser) -> None:
    """Add logging configuration arguments."""
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


def _add_connection_limit_args(parser: argparse.ArgumentParser) -> None:
    """Add connection and rate-limit arguments."""
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


def _add_timeout_args(parser: argparse.ArgumentParser) -> None:
    """Add socket and shutdown timeout arguments."""
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
        "--header-read-timeout",
        type=float,
        default=DEFAULT_HEADER_READ_TIMEOUT,
        help="Deadline in seconds to finish reading request headers",
    )
    parser.add_argument(
        "--body-read-timeout",
        type=float,
        default=DEFAULT_BODY_READ_TIMEOUT,
        help="Deadline in seconds to finish reading the request body",
    )
    parser.add_argument(
        "--handler-timeout",
        type=float,
        default=DEFAULT_HANDLER_TIMEOUT,
        help="Deadline in seconds for handler execution and response writing",
    )


def _add_cors_args(parser: argparse.ArgumentParser) -> None:
    """Add CORS configuration arguments."""
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


def _add_auth_args(parser: argparse.ArgumentParser) -> None:
    """Add authentication and authorization arguments."""
    parser.add_argument(
        "--auth-mode",
        choices=["none", "api-key", "basic", "jwt"],
        default=DEFAULT_AUTH_MODE,
        help="Authentication mode (default: none)",
    )
    parser.add_argument(
        "--auth-credentials",
        default=DEFAULT_AUTH_CREDENTIALS,
        help="Comma-separated identity:sha256hex api-key credentials",
    )
    parser.add_argument(
        "--auth-roles",
        default=DEFAULT_AUTH_ROLES,
        help="Comma-separated identity:scope|scope role assignments",
    )
    parser.add_argument(
        "--jwt-secret",
        default=DEFAULT_JWT_SECRET,
        help="Shared secret for HS256 JWT verification",
    )
    parser.add_argument(
        "--jwt-issuer",
        default=DEFAULT_JWT_ISSUER,
        help="Expected JWT issuer (iss) claim",
    )
    parser.add_argument(
        "--jwt-audience",
        default=DEFAULT_JWT_AUDIENCE,
        help="Expected JWT audience (aud) claim",
    )


def _add_observability_args(parser: argparse.ArgumentParser) -> None:
    """Add observability/metrics arguments."""
    parser.add_argument(
        "--metrics",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_METRICS_ENABLED,
        help="Expose a Prometheus /metrics endpoint",
    )
    parser.add_argument(
        "--error-format",
        choices=["text", "json"],
        default=DEFAULT_ERROR_FORMAT,
        help="Error response body format (default: text)",
    )
    parser.add_argument(
        "--enable-sse",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_ENABLE_SSE,
        help="Expose a Server-Sent Events stream at /events",
    )
    parser.add_argument(
        "--enable-websocket",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_ENABLE_WEBSOCKET,
        help="Expose a WebSocket echo endpoint at /ws",
    )


def _add_session_args(parser: argparse.ArgumentParser) -> None:
    """Add signed-session-cookie arguments."""
    parser.add_argument(
        "--session-secret",
        default=DEFAULT_SESSION_SECRET,
        help="HMAC secret enabling signed session cookies (empty disables)",
    )
    parser.add_argument(
        "--session-ttl",
        type=int,
        default=DEFAULT_SESSION_TTL,
        help="Session lifetime in seconds (sliding expiry)",
    )
    parser.add_argument(
        "--session-cookie-secure",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_SESSION_COOKIE_SECURE,
        help="Mark the session cookie Secure (TLS-only)",
    )
    parser.add_argument(
        "--session-cookie-samesite",
        choices=["Strict", "Lax", "None"],
        default=DEFAULT_SESSION_COOKIE_SAMESITE,
        help="SameSite attribute for the session cookie",
    )


def _add_request_framing_args(parser: argparse.ArgumentParser) -> None:
    """Add opt-in request-body framing arguments."""
    parser.add_argument(
        "--allow-chunked-requests",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_ALLOW_CHUNKED_REQUESTS,
        help="Decode Transfer-Encoding: chunked request bodies (default: off)",
    )
    parser.add_argument(
        "--expect-continue",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_EXPECT_CONTINUE,
        help="Honor Expect: 100-continue before reading request bodies",
    )


def _add_file_serving_args(parser: argparse.ArgumentParser) -> None:
    """Add static file serving arguments."""
    parser.add_argument(
        "--file-cache-control",
        default=DEFAULT_FILE_CACHE_CONTROL,
        help="Cache-Control header value for file responses (empty to omit)",
    )
    parser.add_argument(
        "--file-gzip",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_FILE_GZIP,
        help="Compress eligible file responses with gzip",
    )
    parser.add_argument(
        "--file-gzip-min-bytes",
        type=int,
        default=DEFAULT_FILE_GZIP_MIN_BYTES,
        help="Minimum file size in bytes before gzip is applied",
    )
    parser.add_argument(
        "--content-sniffing",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_CONTENT_SNIFFING,
        help="Sniff content type from magic bytes when the extension is unknown",
    )


def parse_cli_args(argv: list[str]) -> argparse.Namespace:
    """Return parsed CLI arguments for server configuration."""
    parser = argparse.ArgumentParser(description="HTTP server configuration")
    parser.add_argument("--directory", default=".")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=4221)
    parser.add_argument("--cert", help="Path to TLS certificate file")
    parser.add_argument("--key", help="Path to TLS private key file")
    _add_logging_args(parser)
    _add_connection_limit_args(parser)
    _add_timeout_args(parser)
    _add_cors_args(parser)
    _add_auth_args(parser)
    _add_observability_args(parser)
    _add_request_framing_args(parser)
    _add_session_args(parser)
    _add_file_serving_args(parser)
    return parser.parse_args(argv)

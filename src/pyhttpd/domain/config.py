"""Static configuration values and CORS settings."""

from dataclasses import dataclass

DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024
FILES_ENDPOINT_PREFIX = "/files/"
ALLOWED_METHODS = {"GET", "POST", "OPTIONS"}
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
}


@dataclass
class CorsConfig:
    """CORS configuration for cross-origin resource sharing."""

    allowed_origins: list[str]
    allowed_methods: list[str]
    allowed_headers: list[str]
    expose_headers: list[str]
    allow_credentials: bool
    max_age: int

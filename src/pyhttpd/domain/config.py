"""Static configuration values and CORS settings."""

from dataclasses import dataclass, field
from typing import Optional

DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024
FILES_ENDPOINT_PREFIX = "/files/"
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"}
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


@dataclass(frozen=True)
class FileServingOptions:
    """Tuning for static file responses (caching and compression)."""

    cache_control: str = ""
    gzip: bool = False
    gzip_min_bytes: int = 1024
    gzip_types: tuple[str, ...] = (
        "text/",
        "application/json",
        "application/javascript",
        "image/svg+xml",
    )


@dataclass
class AuthConfig:
    """Authentication settings shared by the auth adapters."""

    mode: str
    credentials: dict[str, str] = field(default_factory=dict)
    roles: dict[str, list[str]] = field(default_factory=dict)
    jwt_secret: str = ""
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None

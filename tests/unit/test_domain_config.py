"""Unit tests for pyhttpd.domain.config constants and CorsConfig."""

from pyhttpd.domain import (
    ALLOWED_METHODS,
    DEFAULT_MAX_BODY_BYTES,
    FILES_ENDPOINT_PREFIX,
    SECURITY_HEADERS,
    CorsConfig,
)


def test_default_max_body_bytes_is_five_mebibytes() -> None:
    """DEFAULT_MAX_BODY_BYTES equals exactly 5 MiB."""
    assert DEFAULT_MAX_BODY_BYTES == 5 * 1024 * 1024


def test_files_endpoint_prefix_value() -> None:
    """FILES_ENDPOINT_PREFIX is the /files/ path prefix."""
    assert FILES_ENDPOINT_PREFIX == "/files/"


def test_allowed_methods_exact_set() -> None:
    """ALLOWED_METHODS contains the supported HTTP method whitelist."""
    assert ALLOWED_METHODS == {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"}


def test_security_headers_exact_mapping() -> None:
    """SECURITY_HEADERS holds the exact three hardening headers and values."""
    assert SECURITY_HEADERS == {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
    }


def test_security_headers_has_three_keys() -> None:
    """SECURITY_HEADERS exposes precisely three keys."""
    assert len(SECURITY_HEADERS) == 3


def test_cors_config_stores_all_fields() -> None:
    """CorsConfig retains every field passed to its constructor."""
    config = CorsConfig(
        allowed_origins=["https://example.com"],
        allowed_methods=["GET", "POST"],
        allowed_headers=["Content-Type"],
        expose_headers=["X-Request-Id"],
        allow_credentials=True,
        max_age=600,
    )
    assert config.allowed_origins == ["https://example.com"]
    assert config.allowed_methods == ["GET", "POST"]
    assert config.allowed_headers == ["Content-Type"]
    assert config.expose_headers == ["X-Request-Id"]
    assert config.allow_credentials is True
    assert config.max_age == 600


def test_cors_config_equality_by_value() -> None:
    """Two CorsConfig instances with identical fields compare equal."""
    first = CorsConfig(
        allowed_origins=["*"],
        allowed_methods=["GET"],
        allowed_headers=[],
        expose_headers=[],
        allow_credentials=False,
        max_age=0,
    )
    second = CorsConfig(
        allowed_origins=["*"],
        allowed_methods=["GET"],
        allowed_headers=[],
        expose_headers=[],
        allow_credentials=False,
        max_age=0,
    )
    assert first == second

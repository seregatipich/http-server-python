"""Public domain API for HTTP server internals."""

from pyhttpd.domain.config import (
    ALLOWED_METHODS,
    DEFAULT_MAX_BODY_BYTES,
    FILES_ENDPOINT_PREFIX,
    SECURITY_HEADERS,
    CorsConfig,
)
from pyhttpd.domain.correlation_id import (
    CorrelationLoggerAdapter,
    clear_correlation_id,
    generate_correlation_id,
    get_correlation_id,
    set_correlation_id,
)
from pyhttpd.domain.errors import ForbiddenPath, RequestEntityTooLarge
from pyhttpd.domain.http import (
    HEADER_DELIMITER,
    HttpRequest,
    HttpResponse,
    format_client_address,
    should_close,
)
from pyhttpd.domain.ports import DrainingState
from pyhttpd.domain.ratelimit import RateLimitDecision, TokenBucketSettings
from pyhttpd.domain.response_builders import (
    accepts_gzip,
    apply_cors_headers,
    bad_request_response,
    compress_if_gzip_supported,
    connection_limited_response,
    determine_allowed_origin,
    draining_response,
    empty_response,
    entity_too_large_response,
    forbidden_response,
    healthz_response,
    is_preflight_request,
    method_not_allowed_response,
    not_found_response,
    preflight_response,
    rate_limited_response,
    text_response,
)
from pyhttpd.domain.sandbox import resolve_sandbox_path
from pyhttpd.domain.token_bucket import TokenBucketLimiter

LifecycleState = DrainingState

__all__ = [
    "ALLOWED_METHODS",
    "DEFAULT_MAX_BODY_BYTES",
    "FILES_ENDPOINT_PREFIX",
    "HEADER_DELIMITER",
    "SECURITY_HEADERS",
    "CorrelationLoggerAdapter",
    "CorsConfig",
    "ForbiddenPath",
    "HttpRequest",
    "HttpResponse",
    "LifecycleState",
    "RateLimitDecision",
    "RequestEntityTooLarge",
    "TokenBucketLimiter",
    "TokenBucketSettings",
    "accepts_gzip",
    "apply_cors_headers",
    "bad_request_response",
    "clear_correlation_id",
    "compress_if_gzip_supported",
    "connection_limited_response",
    "determine_allowed_origin",
    "draining_response",
    "empty_response",
    "entity_too_large_response",
    "format_client_address",
    "forbidden_response",
    "generate_correlation_id",
    "get_correlation_id",
    "healthz_response",
    "is_preflight_request",
    "method_not_allowed_response",
    "not_found_response",
    "preflight_response",
    "rate_limited_response",
    "resolve_sandbox_path",
    "set_correlation_id",
    "should_close",
    "text_response",
]

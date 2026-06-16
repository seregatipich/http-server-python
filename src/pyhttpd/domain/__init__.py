"""Public domain API for HTTP server internals."""

from pyhttpd.domain.config import (
    ALLOWED_METHODS,
    DEFAULT_MAX_BODY_BYTES,
    FILES_ENDPOINT_PREFIX,
    SECURITY_HEADERS,
    CorsConfig,
)
from pyhttpd.domain.errors import (
    BadRequest,
    Forbidden,
    ForbiddenPath,
    HttpError,
    InternalServerError,
    MethodNotAllowed,
    NotFound,
    RateLimited,
    RequestEntityTooLarge,
    ServiceUnavailable,
)
from pyhttpd.domain.http import HttpRequest, HttpResponse, should_close
from pyhttpd.domain.ports import DrainingState, Logger, RateLimiter
from pyhttpd.domain.ratelimit import RateLimitDecision, TokenBucketSettings
from pyhttpd.domain.sandbox import resolve_sandbox_path

LifecycleState = DrainingState

__all__ = [
    "ALLOWED_METHODS",
    "DEFAULT_MAX_BODY_BYTES",
    "FILES_ENDPOINT_PREFIX",
    "SECURITY_HEADERS",
    "CorsConfig",
    "BadRequest",
    "Forbidden",
    "ForbiddenPath",
    "HttpError",
    "HttpRequest",
    "HttpResponse",
    "InternalServerError",
    "LifecycleState",
    "Logger",
    "MethodNotAllowed",
    "NotFound",
    "RateLimitDecision",
    "RateLimited",
    "RateLimiter",
    "RequestEntityTooLarge",
    "ServiceUnavailable",
    "TokenBucketSettings",
    "resolve_sandbox_path",
    "should_close",
]

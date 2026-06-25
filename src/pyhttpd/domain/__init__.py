"""Public domain API for HTTP server internals."""

from pyhttpd.domain.config import (
    ALLOWED_METHODS,
    DEFAULT_MAX_BODY_BYTES,
    FILES_ENDPOINT_PREFIX,
    SECURITY_HEADERS,
    AuthConfig,
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
    Unauthorized,
)
from pyhttpd.domain.http import HttpRequest, HttpResponse, should_close
from pyhttpd.domain.metrics import HISTOGRAM_BUCKETS_SECONDS, MetricsSink
from pyhttpd.domain.ports import (
    Authenticator,
    Clock,
    DrainingState,
    IdGenerator,
    Logger,
    RateLimiter,
)
from pyhttpd.domain.principal import (
    DEFAULT_AUTH_MODE,
    RBAC_POLICY,
    Principal,
    required_scope,
)
from pyhttpd.domain.ratelimit import RateLimitDecision, TokenBucketSettings
from pyhttpd.domain.sandbox import resolve_sandbox_path

LifecycleState = DrainingState

__all__ = [
    "ALLOWED_METHODS",
    "DEFAULT_AUTH_MODE",
    "DEFAULT_MAX_BODY_BYTES",
    "FILES_ENDPOINT_PREFIX",
    "RBAC_POLICY",
    "SECURITY_HEADERS",
    "AuthConfig",
    "Authenticator",
    "CorsConfig",
    "BadRequest",
    "Clock",
    "Forbidden",
    "ForbiddenPath",
    "HttpError",
    "IdGenerator",
    "HISTOGRAM_BUCKETS_SECONDS",
    "HttpRequest",
    "HttpResponse",
    "InternalServerError",
    "MetricsSink",
    "LifecycleState",
    "Logger",
    "MethodNotAllowed",
    "NotFound",
    "Principal",
    "RateLimitDecision",
    "RateLimited",
    "RateLimiter",
    "RequestEntityTooLarge",
    "ServiceUnavailable",
    "TokenBucketSettings",
    "Unauthorized",
    "required_scope",
    "resolve_sandbox_path",
    "should_close",
]

"""Public domain API for HTTP server internals."""

from pyhttpd.domain.byte_range import UNSATISFIABLE_RANGE, ByteRange, parse_range
from pyhttpd.domain.config import (
    ALLOWED_METHODS,
    DEFAULT_MAX_BODY_BYTES,
    FILES_ENDPOINT_PREFIX,
    SECURITY_HEADERS,
    AuthConfig,
    CorsConfig,
    FileServingOptions,
)
from pyhttpd.domain.errors import (
    BadRequest,
    Forbidden,
    ForbiddenPath,
    HttpError,
    InternalServerError,
    MethodNotAllowed,
    NotFound,
    RangeNotSatisfiable,
    RateLimited,
    RequestEntityTooLarge,
    RequestTimeout,
    ServiceUnavailable,
    Unauthorized,
)
from pyhttpd.domain.file_metadata import (
    FileMetadata,
    compute_etag,
    http_date,
    is_not_modified,
    parse_http_date,
)
from pyhttpd.domain.forms import (
    FormPart,
    parse_multipart,
    parse_query,
    parse_urlencoded,
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
from pyhttpd.domain.sniff import sniff_content_type
from pyhttpd.domain.timeouts import PhaseTimeouts

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
    "ByteRange",
    "CorsConfig",
    "BadRequest",
    "Clock",
    "FileMetadata",
    "FileServingOptions",
    "FormPart",
    "parse_multipart",
    "parse_query",
    "parse_urlencoded",
    "RangeNotSatisfiable",
    "UNSATISFIABLE_RANGE",
    "compute_etag",
    "http_date",
    "is_not_modified",
    "parse_http_date",
    "parse_range",
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
    "PhaseTimeouts",
    "Principal",
    "RequestTimeout",
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
    "sniff_content_type",
]

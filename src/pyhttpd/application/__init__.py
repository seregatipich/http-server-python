"""Application layer: middleware pipeline and request handlers."""

from pyhttpd.application.context import RequestContext
from pyhttpd.application.cors_headers import (
    apply_cors_headers,
    determine_allowed_origin,
    is_preflight_request,
    preflight_response,
)
from pyhttpd.application.handlers.echo import make_echo_handler
from pyhttpd.application.handlers.files import make_files_handler, make_index_handler
from pyhttpd.application.handlers.healthz import make_healthz_handler
from pyhttpd.application.handlers.user_agent import make_user_agent_handler
from pyhttpd.application.middleware.auth import make_auth_middleware
from pyhttpd.application.middleware.cors import make_cors_middleware
from pyhttpd.application.middleware.metrics import make_metrics_middleware
from pyhttpd.application.middleware.rate_limit import (
    RateLimitOutcome,
    classify,
    make_rate_limit_middleware,
)
from pyhttpd.application.middleware.validation import make_validation_middleware
from pyhttpd.application.pipeline import Handler, Middleware, build_chain
from pyhttpd.application.rendering import (
    ErrorMapper,
    accepts_gzip,
    compress_if_gzip_supported,
    connection_limited_response,
    internal_error_response,
    method_not_allowed_response,
    rate_limited_response,
    unauthorized_response,
)
from pyhttpd.application.routing import make_default_router

__all__ = [
    "RequestContext",
    "apply_cors_headers",
    "determine_allowed_origin",
    "is_preflight_request",
    "preflight_response",
    "make_echo_handler",
    "make_files_handler",
    "make_index_handler",
    "make_healthz_handler",
    "make_user_agent_handler",
    "make_auth_middleware",
    "make_cors_middleware",
    "make_metrics_middleware",
    "RateLimitOutcome",
    "classify",
    "make_rate_limit_middleware",
    "make_validation_middleware",
    "Handler",
    "Middleware",
    "build_chain",
    "ErrorMapper",
    "accepts_gzip",
    "compress_if_gzip_supported",
    "connection_limited_response",
    "internal_error_response",
    "method_not_allowed_response",
    "rate_limited_response",
    "unauthorized_response",
    "make_default_router",
]

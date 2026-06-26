"""Assembles the application middleware chain over a routed terminal.

The transport worker builds the router and supplies its ``dispatch`` callable;
this module owns the cross-cutting middleware ordering so adding or reordering a
middleware never touches the transport adapter.
"""

from dataclasses import replace
from typing import Optional

from pyhttpd.application.context import RequestContext
from pyhttpd.application.middleware.auth import make_auth_middleware
from pyhttpd.application.middleware.cors import make_cors_middleware
from pyhttpd.application.middleware.metrics import make_metrics_middleware
from pyhttpd.application.middleware.rate_limit import make_rate_limit_middleware
from pyhttpd.application.middleware.validation import make_validation_middleware
from pyhttpd.application.pipeline import Handler, build_chain
from pyhttpd.application.rendering import ErrorMapper
from pyhttpd.domain import (
    ALLOWED_METHODS,
    SECURITY_HEADERS,
    Authenticator,
    CorsConfig,
    HttpError,
    HttpRequest,
    HttpResponse,
    Logger,
    MetricsSink,
    RateLimiter,
)

_KNOWN_ROUTE_LABELS = ("/healthz", "/user-agent", "/metrics", "/")


def route_label(request: HttpRequest) -> str:
    """Map a request to a bounded metric route label (never client-controlled)."""
    if request.path.startswith("/echo/"):
        return "/echo/"
    if request.path.startswith("/files/"):
        return "/files/"
    if request.path in _KNOWN_ROUTE_LABELS:
        return request.path
    return "other"


def _strip_body_for_head(response: HttpResponse) -> HttpResponse:
    """Return a HEAD response: same headers as GET, no body."""
    if response.use_chunked:
        # Preserve Transfer-Encoding: chunked semantics; emit no body and no
        # misleading Content-Length for a resource of unknown length.
        return replace(response, body=b"", body_iter=None)
    length = response.content_length
    if length is None:
        length = len(response.body)
    return replace(
        response,
        body=b"",
        body_iter=None,
        content_length=length,
    )


def build_request_chain(
    dispatch: Handler,
    *,
    cors_config: Optional[CorsConfig],
    metrics_sink: Optional[MetricsSink],
    rate_limiter: Optional[RateLimiter],
    authenticator: Optional[Authenticator],
    logger: Logger,
    client_ip: str,
    max_body_bytes: int,
) -> Handler:
    """Wrap ``dispatch`` in the ordered application middleware chain."""

    def terminal(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        is_head = request.method == "HEAD"
        dispatch_request = replace(request, method="GET") if is_head else request
        try:
            response = dispatch(dispatch_request, ctx)
        except HttpError as error:
            response = ErrorMapper.to_response(error, request, cors_config)
        if is_head:
            response = _strip_body_for_head(response)
        if ctx.rate_decision is not None:
            response.headers.update(ctx.rate_decision.headers)
        return response

    middlewares = []
    if metrics_sink is not None:
        middlewares.append(make_metrics_middleware(metrics_sink, route_label))
    middlewares.append(make_cors_middleware(cors_config, SECURITY_HEADERS))
    if rate_limiter is not None:
        middlewares.append(
            make_rate_limit_middleware(
                rate_limiter,
                logger,
                lambda request, ctx: client_ip,
                metrics_sink,
            )
        )
    middlewares.append(make_validation_middleware(ALLOWED_METHODS, max_body_bytes))
    if authenticator is not None:
        middlewares.append(make_auth_middleware(authenticator, logger))
    return build_chain(middlewares, terminal)

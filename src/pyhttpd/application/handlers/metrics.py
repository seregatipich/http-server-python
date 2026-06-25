"""Handler for /metrics Prometheus exposition requests."""

from typing import Callable

from pyhttpd.application.context import RequestContext
from pyhttpd.domain import (
    SECURITY_HEADERS,
    HttpRequest,
    HttpResponse,
    MetricsSink,
    should_close,
)

RouteHandler = Callable[[HttpRequest, RequestContext], HttpResponse]

_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def make_metrics_handler(sink: MetricsSink) -> RouteHandler:
    """Build a handler exposing the Prometheus text exposition."""

    def handle(request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        return HttpResponse(
            "HTTP/1.1 200 OK",
            {"Content-Type": _CONTENT_TYPE, **SECURITY_HEADERS},
            sink.render(),
            close_connection=should_close(request.headers),
        )

    return handle

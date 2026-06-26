"""Metrics collection middleware for the application pipeline."""

import time
from typing import Callable

from pyhttpd.application.context import RequestContext
from pyhttpd.application.pipeline import Handler, Middleware
from pyhttpd.domain import HttpError, HttpRequest, HttpResponse, MetricsSink

RouteLabeler = Callable[[HttpRequest], str]

_METRICS_PATH = "/metrics"


def _status_of(status_line: str) -> int:
    try:
        return int(status_line.split(" ", 2)[1])
    except (IndexError, ValueError):
        return 0


def make_metrics_middleware(
    sink: MetricsSink, route_label_of: RouteLabeler
) -> Middleware:
    """Build middleware that records request, latency, and error metrics."""

    def middleware(
        request: HttpRequest, ctx: RequestContext, nxt: Handler
    ) -> HttpResponse:
        if request.path == _METRICS_PATH:
            return nxt(request, ctx)

        route = route_label_of(request)
        sink.inc_in_flight()
        start_ns = time.monotonic_ns()
        try:
            response = nxt(request, ctx)
        except HttpError as error:
            if error.status >= 500:
                sink.inc_error(request.method, route)
            sink.observe_request(
                request.method,
                route,
                error.status,
                (time.monotonic_ns() - start_ns) / 1_000_000_000,
            )
            raise
        except Exception:
            sink.inc_error(request.method, route)
            sink.observe_request(
                request.method,
                route,
                500,
                (time.monotonic_ns() - start_ns) / 1_000_000_000,
            )
            raise
        finally:
            sink.dec_in_flight()

        status = _status_of(response.status_line)
        if status >= 500:
            sink.inc_error(request.method, route)
        sink.observe_request(
            request.method,
            route,
            status,
            (time.monotonic_ns() - start_ns) / 1_000_000_000,
        )
        return response

    return middleware

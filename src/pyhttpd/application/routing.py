"""Request routing for the application pipeline."""

from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Protocol

from pyhttpd.application.context import RequestContext
from pyhttpd.application.handlers.echo import make_echo_handler
from pyhttpd.application.handlers.files import make_files_handler, make_index_handler
from pyhttpd.application.handlers.healthz import make_healthz_handler
from pyhttpd.application.handlers.metrics import make_metrics_handler
from pyhttpd.application.handlers.sse import make_sse_handler
from pyhttpd.application.handlers.user_agent import make_user_agent_handler
from pyhttpd.application.handlers.websocket import make_websocket_handler
from pyhttpd.domain import (
    FILES_ENDPOINT_PREFIX,
    CorsConfig,
    DrainingState,
    FileServingOptions,
    HttpRequest,
    HttpResponse,
    Logger,
    MetricsSink,
    NotFound,
)


class RouteHandler(Protocol):
    """Callable that turns a matched request into a response."""

    def __call__(
        self, request: HttpRequest, ctx: RequestContext, /
    ) -> HttpResponse: ...


@dataclass(frozen=True)
class Route:
    """Pairs a request predicate with the handler that serves it."""

    matches: Callable[[HttpRequest], bool]
    handler: RouteHandler


class Router:
    """Dispatches requests to the first matching route."""

    def __init__(self, routes: Iterable[Route]) -> None:
        self._routes = tuple(routes)

    def dispatch(self, request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        """Return the response from the first matching route."""
        for route in self._routes:
            if route.matches(request):
                return route.handler(request, ctx)
        raise NotFound("no matching route")


Dispatch = Callable[[HttpRequest, RequestContext], HttpResponse]


def normalize_host(host: str) -> str:
    """Lowercase a Host header and strip any port for vhost matching."""
    return host.split(":", 1)[0].strip().lower()


def make_vhost_router(
    host_directories: dict[str, str],
    default_directory: str,
    build_router: Callable[[str], Router],
) -> Dispatch:
    """Dispatch to a per-host router by Host header, falling back to default."""
    routers = {
        normalize_host(host): build_router(directory)
        for host, directory in host_directories.items()
    }
    default_router = build_router(default_directory)

    def dispatch(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        host = normalize_host(request.headers.get("host", ""))
        return routers.get(host, default_router).dispatch(request, ctx)

    return dispatch


def make_default_router(
    directory: str,
    draining_state: Optional[DrainingState],
    logger: Logger,
    cors_config: Optional[CorsConfig] = None,
    metrics_sink: Optional[MetricsSink] = None,
    file_options: Optional[FileServingOptions] = None,
    enable_sse: bool = False,
    enable_websocket: bool = False,
) -> Router:
    """Wire the default route table in legacy match order."""
    healthz = make_healthz_handler(draining_state, logger)
    index = make_index_handler(directory, logger, cors_config)
    echo = make_echo_handler(logger, cors_config)
    user_agent = make_user_agent_handler(logger, cors_config)
    files = make_files_handler(directory, logger, cors_config, file_options)
    routes = [
        Route(lambda request: request.path == "/healthz", healthz),
        Route(lambda request: request.path == "/", index),
        Route(lambda request: request.path.startswith("/echo/"), echo),
        Route(lambda request: request.path == "/user-agent", user_agent),
        Route(lambda request: request.path.startswith(FILES_ENDPOINT_PREFIX), files),
    ]
    _append_optional_routes(
        routes, draining_state, logger, metrics_sink, enable_sse, enable_websocket
    )
    return Router(routes)


def _append_optional_routes(
    routes: list[Route],
    draining_state: Optional[DrainingState],
    logger: Logger,
    metrics_sink: Optional[MetricsSink],
    enable_sse: bool,
    enable_websocket: bool,
) -> None:
    """Append the opt-in metrics, SSE, and WebSocket routes when enabled."""
    if metrics_sink is not None:
        metrics = make_metrics_handler(metrics_sink)
        routes.append(Route(lambda request: request.path == "/metrics", metrics))
    if enable_sse:
        sse = make_sse_handler(draining_state, logger)
        routes.append(Route(lambda request: request.path == "/events", sse))
    if enable_websocket:
        websocket = make_websocket_handler(draining_state, logger)
        routes.append(Route(lambda request: request.path == "/ws", websocket))

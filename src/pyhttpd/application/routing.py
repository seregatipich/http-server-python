"""Request routing for the application pipeline."""

from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Protocol

from pyhttpd.application.context import RequestContext
from pyhttpd.application.handlers.echo import make_echo_handler
from pyhttpd.application.handlers.files import make_files_handler, make_index_handler
from pyhttpd.application.handlers.healthz import make_healthz_handler
from pyhttpd.application.handlers.user_agent import make_user_agent_handler
from pyhttpd.domain import (
    FILES_ENDPOINT_PREFIX,
    CorsConfig,
    DrainingState,
    HttpRequest,
    HttpResponse,
    Logger,
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


def make_default_router(
    directory: str,
    draining_state: Optional[DrainingState],
    logger: Logger,
    cors_config: Optional[CorsConfig] = None,
) -> Router:
    """Wire the default route table in legacy match order."""
    healthz = make_healthz_handler(draining_state, logger)
    index = make_index_handler(directory, logger, cors_config)
    echo = make_echo_handler(logger, cors_config)
    user_agent = make_user_agent_handler(logger, cors_config)
    files = make_files_handler(directory, logger, cors_config)
    routes = (
        Route(lambda request: request.path == "/healthz", healthz),
        Route(lambda request: request.path == "/", index),
        Route(lambda request: request.path.startswith("/echo/"), echo),
        Route(lambda request: request.path == "/user-agent", user_agent),
        Route(lambda request: request.path.startswith(FILES_ENDPOINT_PREFIX), files),
    )
    return Router(routes)

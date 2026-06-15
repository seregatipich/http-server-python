"""Request routing logic."""

import logging
from dataclasses import dataclass
from typing import Optional

from pyhttpd.adapters.logging.correlation_adapter import CorrelationLoggerAdapter
from pyhttpd.domain import (
    FILES_ENDPOINT_PREFIX,
    SECURITY_HEADERS,
    CorsConfig,
    HttpRequest,
    HttpResponse,
    LifecycleState,
    forbidden_response,
    not_found_response,
)
from pyhttpd.handlers import (
    file_response,
    handle_echo,
    handle_healthz,
    handle_user_agent,
    index_response,
)

ROUTER_LOGGER = CorrelationLoggerAdapter(
    logging.getLogger("http_server.pipeline.router"), {}
)


@dataclass(frozen=True)
class RouteContext:
    """Request-scoped values shared by route handlers."""

    request: HttpRequest
    directory: str
    lifecycle: Optional[LifecycleState]
    cors_config: Optional[CorsConfig]


def _log_route_match(route: str) -> None:
    if ROUTER_LOGGER.logger.isEnabledFor(logging.DEBUG):
        ROUTER_LOGGER.debug(
            "Route matched", extra={"event": "route_matched", "route": route}
        )


def _route_healthz(context: RouteContext) -> Optional[HttpResponse]:
    if context.request.path != "/healthz":
        return None
    _log_route_match("/healthz")
    return handle_healthz(context.lifecycle, SECURITY_HEADERS)


def _route_index(context: RouteContext) -> Optional[HttpResponse]:
    if context.request.path != "/":
        return None
    _log_route_match("/")
    return index_response(
        context.request,
        context.directory,
        context.cors_config,
        SECURITY_HEADERS,
    )


def _route_echo(context: RouteContext) -> Optional[HttpResponse]:
    if not context.request.path.startswith("/echo/"):
        return None
    _log_route_match("/echo/*")
    return handle_echo(context.request, context.cors_config, SECURITY_HEADERS)


def _route_user_agent(context: RouteContext) -> Optional[HttpResponse]:
    if context.request.path != "/user-agent":
        return None
    _log_route_match("/user-agent")
    return handle_user_agent(context.request, context.cors_config, SECURITY_HEADERS)


def _is_invalid_file_route(remainder: str) -> bool:
    return (
        not remainder
        or remainder.startswith("../")
        or "/../" in remainder
        or remainder.startswith("..")
    )


def _route_file(context: RouteContext) -> Optional[HttpResponse]:
    request = context.request
    if not request.path.startswith(FILES_ENDPOINT_PREFIX):
        return None

    remainder = request.path[len(FILES_ENDPOINT_PREFIX) :]
    if _is_invalid_file_route(remainder):
        ROUTER_LOGGER.warning(
            "Invalid file path in request",
            extra={"event": "route_invalid", "route": request.path},
        )
        return forbidden_response(request, context.cors_config, SECURITY_HEADERS)

    _log_route_match("/files/*")
    return file_response(
        request,
        context.directory,
        context.cors_config,
        SECURITY_HEADERS,
        FILES_ENDPOINT_PREFIX,
    )


ROUTE_HANDLERS = (
    _route_healthz,
    _route_index,
    _route_echo,
    _route_user_agent,
    _route_file,
)


def route_request(
    request: HttpRequest,
    directory: str,
    lifecycle: Optional[LifecycleState] = None,
    cors_config: Optional[CorsConfig] = None,
) -> HttpResponse:
    """Route the request to the appropriate handler and return a response."""
    context = RouteContext(request, directory, lifecycle, cors_config)
    for handler in ROUTE_HANDLERS:
        response = handler(context)
        if response is not None:
            return response

    ROUTER_LOGGER.info(
        "No matching route found",
        extra={
            "event": "route_not_found",
            "route": request.path,
            "method": request.method,
        },
    )
    return not_found_response(request, cors_config, SECURITY_HEADERS)

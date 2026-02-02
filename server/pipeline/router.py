"""Request routing logic."""

from typing import Optional

from server.bootstrap.config import FILES_ENDPOINT_PREFIX, SECURITY_HEADERS
from server.domain.http_types import HttpRequest, HttpResponse
from server.domain.response_builders import (
    forbidden_response,
    not_found_response,
)
from server.handlers.file_handler import file_response, index_response
from server.handlers.system_handlers import (
    handle_echo,
    handle_healthz,
    handle_user_agent,
)
from server.lifecycle.state import ServerLifecycle
from server.security.cors import CorsConfig


def route_request(
    request: HttpRequest,
    directory: str,
    lifecycle: Optional[ServerLifecycle] = None,
    cors_config: Optional[CorsConfig] = None,
) -> HttpResponse:
    """Route the request to the appropriate handler and return a response."""
    if request.path == "/healthz":
        return handle_healthz(lifecycle)

    if request.path == "/":
        return index_response(
            request,
            directory,
            cors_config,
            SECURITY_HEADERS,
        )

    if request.path.startswith("/echo/"):
        return handle_echo(request, cors_config)

    if request.path == "/user-agent":
        return handle_user_agent(request, cors_config)

    if request.path.startswith(FILES_ENDPOINT_PREFIX):
        remainder = request.path[len(FILES_ENDPOINT_PREFIX) :]
        is_invalid = (
            not remainder
            or remainder.startswith("../")
            or "/../" in remainder
            or remainder.startswith("..")
        )
        return (
            forbidden_response(request, cors_config, SECURITY_HEADERS)
            if is_invalid
            else file_response(
                request,
                directory,
                cors_config,
                SECURITY_HEADERS,
                FILES_ENDPOINT_PREFIX,
            )
        )

    return not_found_response(request, cors_config, SECURITY_HEADERS)

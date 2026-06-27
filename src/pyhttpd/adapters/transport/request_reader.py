"""Reading and validating a single request off the client socket."""

import logging
import socket
from typing import Optional

from pyhttpd.adapters.logging.correlation_adapter import get_correlation_id
from pyhttpd.adapters.transport.io import (
    _recv_with_deadline,
    receive_request,
    send_response,
)
from pyhttpd.adapters.transport.wire import format_client_address
from pyhttpd.adapters.transport.worker_logging import WORKER_LOGGER
from pyhttpd.application.rendering import (
    apply_error_format,
    bad_request_response,
    entity_too_large_response,
    forbidden_response,
    request_timeout_response,
)
from pyhttpd.domain import (
    SECURITY_HEADERS,
    ForbiddenPath,
    HttpRequest,
    HttpResponse,
    PhaseTimeouts,
    RequestEntityTooLarge,
    RequestTimeout,
)

__all__ = ["_read_request_with_validation", "_recv_with_deadline"]


def _reject(
    client_socket: socket.socket,
    client_address: tuple[str, int],
    message: str,
    event: str,
    response: HttpResponse,
    error_format: str = "text",
) -> tuple[Optional[HttpRequest], bytes, bool]:
    """Log a rejected request, send the error response, and signal termination."""
    WORKER_LOGGER.warning(
        message,
        extra={"event": event, "client": format_client_address(client_address)},
    )
    send_response(
        client_socket, apply_error_format(response, error_format, get_correlation_id())
    )
    return None, b"", True


def _read_request_with_validation(
    client_socket: socket.socket,
    buffer: bytes,
    client_address: tuple[str, int],
    max_body_bytes: int,
    timeouts: Optional[PhaseTimeouts] = None,
    error_format: str = "text",
    allow_chunked: bool = False,
    expect_continue: bool = False,
) -> tuple[Optional[HttpRequest], bytes, bool]:
    """Read a request from the socket while enforcing size and path limits."""

    try:
        request, buffer = receive_request(
            client_socket,
            buffer,
            max_body_bytes,
            timeouts,
            allow_chunked=allow_chunked,
            expect_continue=expect_continue,
        )
    except RequestTimeout:
        return _reject(
            client_socket,
            client_address,
            "Client too slow to send request",
            "request_timeout",
            request_timeout_response(SECURITY_HEADERS),
            error_format,
        )
    except RequestEntityTooLarge:
        WORKER_LOGGER.warning(
            "Request body size exceeded limit",
            extra={
                "event": "body_size_exceeded",
                "client": format_client_address(client_address),
                "limit": max_body_bytes,
            },
        )
        send_response(
            client_socket,
            apply_error_format(
                entity_too_large_response(SECURITY_HEADERS),
                error_format,
                get_correlation_id(),
            ),
        )
        return None, b"", True
    except ForbiddenPath:
        return _reject(
            client_socket,
            client_address,
            "Forbidden path access attempt",
            "forbidden_path",
            forbidden_response(None, None, SECURITY_HEADERS),
            error_format,
        )
    except ValueError:
        return _reject(
            client_socket,
            client_address,
            "Malformed request received",
            "malformed_request",
            bad_request_response(None, None, SECURITY_HEADERS),
            error_format,
        )

    if request is None:
        client_addr_str = format_client_address(client_address)
        if WORKER_LOGGER.logger.isEnabledFor(logging.DEBUG):
            WORKER_LOGGER.debug(
                "Client disconnected during request",
                extra={"event": "client_disconnected", "client": client_addr_str},
            )
        return None, buffer, True
    return request, buffer, False

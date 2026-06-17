"""Reading and validating a single request off the client socket."""

import logging
import socket
import time
from typing import Optional

from pyhttpd.adapters.transport.io import receive_request, send_response
from pyhttpd.adapters.transport.wire import format_client_address
from pyhttpd.adapters.transport.worker_logging import WORKER_LOGGER
from pyhttpd.application.rendering import (
    bad_request_response,
    entity_too_large_response,
    forbidden_response,
)
from pyhttpd.domain import (
    SECURITY_HEADERS,
    ForbiddenPath,
    HttpRequest,
    HttpResponse,
    RequestEntityTooLarge,
)


def _recv_with_deadline(client_socket: socket.socket, deadline_ns: int) -> bytes:
    """Receive data from socket with a deadline, raising TimeoutError if exceeded."""
    remaining_ns = deadline_ns - time.monotonic_ns()
    if remaining_ns <= 0:
        raise TimeoutError("Request deadline exceeded")
    timeout_seconds = remaining_ns / 1_000_000_000
    client_socket.settimeout(timeout_seconds)
    return client_socket.recv(4096)


def _reject(
    client_socket: socket.socket,
    client_address: tuple[str, int],
    message: str,
    event: str,
    response: HttpResponse,
    extra: Optional[dict[str, object]] = None,
) -> tuple[Optional[HttpRequest], bytes, bool]:
    """Log a rejected request, send the error response, and signal termination."""
    fields: dict[str, object] = {
        "event": event,
        "client": format_client_address(client_address),
    }
    if extra:
        fields.update(extra)
    WORKER_LOGGER.warning(message, extra=fields)
    send_response(client_socket, response)
    return None, b"", True


def _read_request_with_validation(
    client_socket: socket.socket,
    buffer: bytes,
    client_address: tuple[str, int],
    max_body_bytes: int,
) -> tuple[Optional[HttpRequest], bytes, bool]:
    """Read a request from the socket while enforcing size and path limits."""

    try:
        request, buffer = receive_request(client_socket, buffer, max_body_bytes)
    except RequestEntityTooLarge:
        return _reject(
            client_socket,
            client_address,
            "Request body size exceeded limit",
            "body_size_exceeded",
            entity_too_large_response(SECURITY_HEADERS),
            {"limit": max_body_bytes},
        )
    except ForbiddenPath:
        return _reject(
            client_socket,
            client_address,
            "Forbidden path access attempt",
            "forbidden_path",
            forbidden_response(None, None, SECURITY_HEADERS),
        )
    except ValueError:
        return _reject(
            client_socket,
            client_address,
            "Malformed request received",
            "malformed_request",
            bad_request_response(None, None, SECURITY_HEADERS),
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

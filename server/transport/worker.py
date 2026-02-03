"""Worker thread logic for handling individual client connections."""

import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

from server.bootstrap.config import ALLOWED_METHODS, MAX_BODY_BYTES, SECURITY_HEADERS
from server.domain.correlation_id import (
    CorrelationLoggerAdapter,
    clear_correlation_id,
    generate_correlation_id,
    set_correlation_id,
)
from server.domain.http_types import HttpRequest
from server.domain.response_builders import (
    bad_request_response,
    draining_response,
    entity_too_large_response,
    forbidden_response,
)
from server.domain.sandbox import ForbiddenPath
from server.pipeline.io import receive_request, send_response
from server.pipeline.rate_limiting import apply_rate_limit
from server.pipeline.router import route_request
from server.pipeline.validation import RequestEntityTooLarge, validate_request
from server.security.cors import CorsConfig, is_preflight_request, preflight_response
from server.transport.context import WorkerContext

WORKER_LOGGER = CorrelationLoggerAdapter(
    logging.getLogger("http_server.transport.worker"), {}
)


def _recv_with_deadline(client_socket: socket.socket, deadline_ns: int) -> bytes:
    """Receive data from socket with a deadline, raising TimeoutError if exceeded."""
    remaining_ns = deadline_ns - time.monotonic_ns()
    if remaining_ns <= 0:
        raise TimeoutError("Request deadline exceeded")
    timeout_seconds = remaining_ns / 1_000_000_000
    client_socket.settimeout(timeout_seconds)
    return client_socket.recv(4096)


def _read_request_with_validation(
    client_socket: socket.socket,
    buffer: bytes,
    client_address: tuple[str, int],
) -> tuple[Optional[HttpRequest], bytes, bool]:
    """Read a request from the socket while enforcing size and path limits."""

    try:
        request, buffer = receive_request(client_socket, buffer)
    except RequestEntityTooLarge:
        client_addr_str = f"{client_address[0]}:{client_address[1]}"
        WORKER_LOGGER.warning(
            "Request body size exceeded limit",
            extra={
                "event": "body_size_exceeded",
                "client": client_addr_str,
                "limit": MAX_BODY_BYTES,
            },
        )
        send_response(client_socket, entity_too_large_response(SECURITY_HEADERS))
        return None, b"", True
    except ForbiddenPath:
        client_addr_str = f"{client_address[0]}:{client_address[1]}"
        WORKER_LOGGER.warning(
            "Forbidden path access attempt",
            extra={"event": "forbidden_path", "client": client_addr_str},
        )
        send_response(client_socket, forbidden_response(None, None, SECURITY_HEADERS))
        return None, b"", True
    except ValueError:
        client_addr_str = f"{client_address[0]}:{client_address[1]}"
        WORKER_LOGGER.warning(
            "Malformed request received",
            extra={"event": "malformed_request", "client": client_addr_str},
        )
        send_response(client_socket, bad_request_response(None, None, SECURITY_HEADERS))
        return None, b"", True

    if request is None:
        client_addr_str = f"{client_address[0]}:{client_address[1]}"
        if WORKER_LOGGER.logger.isEnabledFor(logging.DEBUG):
            WORKER_LOGGER.debug(
                "Client disconnected during request",
                extra={"event": "client_disconnected", "client": client_addr_str},
            )
        return None, buffer, True
    return request, buffer, False


def _handle_validation_response(
    request: HttpRequest,
    client_socket: socket.socket,
    cors_config: Optional[CorsConfig],
) -> tuple[bool, bool]:
    validation_response = validate_request(
        request, ALLOWED_METHODS, MAX_BODY_BYTES, cors_config, SECURITY_HEADERS
    )
    if validation_response is None:
        return False, False
    send_response(client_socket, validation_response)
    return True, validation_response.close_connection


def _process_request(
    request: HttpRequest,
    context: WorkerContext,
    client_socket: socket.socket,
    client_address: tuple[str, int],
    client_ip: str,
) -> bool:
    if is_preflight_request(request):
        response = preflight_response(request, context.cors_config, SECURITY_HEADERS)
        send_response(client_socket, response)
        return response.close_connection

    rate_decision, should_stop, should_close = apply_rate_limit(
        context.rate_limiter,
        client_ip,
        client_socket,
        client_address,
        request,
    )
    if should_stop:
        return should_close

    handled, validation_requires_close = _handle_validation_response(
        request, client_socket, context.cors_config
    )
    if handled:
        return validation_requires_close

    response = route_request(
        request, context.directory, context.lifecycle, context.cors_config
    )
    if rate_decision is not None:
        response.headers.update(rate_decision.headers)
    send_response(client_socket, response)
    return response.close_connection


def _prepare_worker(
    context: WorkerContext,
    client_socket: socket.socket,
    current_thread: threading.Thread,
):
    lifecycle = context.lifecycle
    if lifecycle is not None:
        lifecycle.register_worker(current_thread)
    if context.config is not None:
        client_socket.settimeout(context.config.socket_timeout)
    return lifecycle


def _drain_if_requested(lifecycle, client_socket: socket.socket) -> bool:
    if lifecycle is None or not lifecycle.is_draining():
        return False
    send_response(client_socket, draining_response(SECURITY_HEADERS))
    return True


@dataclass
class _WorkerResources:
    thread: threading.Thread
    client_socket: socket.socket
    client_ip: str
    client_addr_str: str


def _cleanup_worker(
    context: WorkerContext,
    lifecycle,
    resources: _WorkerResources,
):
    if context.connection_limiter is not None:
        context.connection_limiter.release(resources.client_ip)
    if lifecycle is not None:
        lifecycle.cleanup_worker(resources.thread)

    try:
        resources.client_socket.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    resources.client_socket.close()

    WORKER_LOGGER.debug(
        "Socket closed",
        extra={"event": "socket_closed", "client": resources.client_addr_str},
    )
    clear_correlation_id()


def handle_client(
    client_socket: socket.socket,
    client_address: tuple[str, int],
    context: WorkerContext,
) -> None:
    """Process requests on a client socket until the connection is closed."""
    buffer = b""
    client_ip = client_address[0]
    current_thread = threading.current_thread()
    lifecycle = _prepare_worker(context, client_socket, current_thread)
    client_addr_str = f"{client_address[0]}:{client_address[1]}"
    resources = _WorkerResources(
        current_thread, client_socket, client_ip, client_addr_str
    )

    try:
        while True:
            correlation_id = generate_correlation_id()
            set_correlation_id(correlation_id)

            WORKER_LOGGER.debug(
                "Request processing started",
                extra={"event": "request_started", "client": client_addr_str},
            )

            if _drain_if_requested(lifecycle, client_socket):
                break

            request, buffer, should_terminate = _read_request_with_validation(
                client_socket,
                buffer,
                client_address,
            )
            if should_terminate:
                clear_correlation_id()
                break

            if request is None:
                clear_correlation_id()
                continue

            WORKER_LOGGER.debug(
                "Request line parsed",
                extra={
                    "event": "request_line_parsed",
                    "method": request.method,
                    "route": request.path,
                },
            )

            should_terminate_connection = _process_request(
                request,
                context,
                client_socket,
                client_address,
                client_ip,
            )

            WORKER_LOGGER.debug(
                "Request processing complete",
                extra={"event": "request_complete", "client": client_addr_str},
            )

            clear_correlation_id()

            if should_terminate_connection:
                break
    except (
        ConnectionError,
        TimeoutError,
        OSError,
        UnicodeDecodeError,
    ) as error:
        WORKER_LOGGER.error(
            "Error handling client connection",
            extra={
                "event": "connection_error",
                "client": client_addr_str,
                "error_type": type(error).__name__,
            },
        )
    except Exception as error:  # pylint: disable=broad-except
        WORKER_LOGGER.error(
            "Unexpected error in worker",
            extra={
                "event": "worker_error",
                "client": client_addr_str,
                "error_type": type(error).__name__,
                "error": str(error),
            },
            exc_info=True,
        )
    finally:
        _cleanup_worker(
            context,
            lifecycle,
            resources,
        )

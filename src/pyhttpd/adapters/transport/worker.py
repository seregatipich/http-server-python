"""Worker thread logic for handling individual client connections."""

import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

from pyhttpd.adapters.logging.correlation_adapter import (
    CorrelationLoggerAdapter,
    clear_correlation_id,
    generate_correlation_id,
    get_correlation_id,
    set_correlation_id,
)
from pyhttpd.adapters.transport.context import WorkerContext
from pyhttpd.adapters.transport.io import receive_request, send_response
from pyhttpd.adapters.transport.wire import format_client_address
from pyhttpd.application.context import RequestContext
from pyhttpd.application.middleware.cors import make_cors_middleware
from pyhttpd.application.middleware.rate_limit import make_rate_limit_middleware
from pyhttpd.application.middleware.validation import make_validation_middleware
from pyhttpd.application.pipeline import build_chain
from pyhttpd.application.rendering import (
    ErrorMapper,
    bad_request_response,
    draining_response,
    entity_too_large_response,
    forbidden_response,
)
from pyhttpd.application.routing import make_default_router
from pyhttpd.domain import (
    ALLOWED_METHODS,
    DEFAULT_MAX_BODY_BYTES,
    SECURITY_HEADERS,
    ForbiddenPath,
    HttpError,
    HttpRequest,
    HttpResponse,
    RequestEntityTooLarge,
    should_close,
)

WORKER_LOGGER = CorrelationLoggerAdapter(
    logging.getLogger("http_server.transport.worker"), {}
)


class _PortLogger:  # pylint: disable=too-few-public-methods
    """Adapt the correlation logger to the structured ports.Logger interface."""

    def __init__(self, adapter: CorrelationLoggerAdapter) -> None:
        self._adapter = adapter

    def log(self, level: int, event: str, **fields: object) -> None:
        """Emit a structured log event through the correlation adapter."""
        self._adapter.log(level, event, extra={"event": event, **fields})


WORKER_PORT_LOGGER = _PortLogger(WORKER_LOGGER)


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
    max_body_bytes: int,
) -> tuple[Optional[HttpRequest], bytes, bool]:
    """Read a request from the socket while enforcing size and path limits."""

    try:
        request, buffer = receive_request(client_socket, buffer, max_body_bytes)
    except RequestEntityTooLarge:
        client_addr_str = format_client_address(client_address)
        WORKER_LOGGER.warning(
            "Request body size exceeded limit",
            extra={
                "event": "body_size_exceeded",
                "client": client_addr_str,
                "limit": max_body_bytes,
            },
        )
        send_response(client_socket, entity_too_large_response(SECURITY_HEADERS))
        return None, b"", True
    except ForbiddenPath:
        client_addr_str = format_client_address(client_address)
        WORKER_LOGGER.warning(
            "Forbidden path access attempt",
            extra={"event": "forbidden_path", "client": client_addr_str},
        )
        send_response(client_socket, forbidden_response(None, None, SECURITY_HEADERS))
        return None, b"", True
    except ValueError:
        client_addr_str = format_client_address(client_address)
        WORKER_LOGGER.warning(
            "Malformed request received",
            extra={"event": "malformed_request", "client": client_addr_str},
        )
        send_response(client_socket, bad_request_response(None, None, SECURITY_HEADERS))
        return None, b"", True

    if request is None:
        client_addr_str = format_client_address(client_address)
        if WORKER_LOGGER.logger.isEnabledFor(logging.DEBUG):
            WORKER_LOGGER.debug(
                "Client disconnected during request",
                extra={"event": "client_disconnected", "client": client_addr_str},
            )
        return None, buffer, True
    return request, buffer, False


def _build_request_chain(context: WorkerContext, client_ip: str, max_body_bytes: int):
    """Assemble the application middleware chain over the default router."""
    router = make_default_router(
        context.directory,
        context.lifecycle,
        WORKER_PORT_LOGGER,
        context.cors_config,
    )

    def terminal(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        try:
            response = router.dispatch(request, ctx)
        except HttpError as error:
            response = ErrorMapper.to_response(error, request, context.cors_config)
        if ctx.rate_decision is not None:
            response.headers.update(ctx.rate_decision.headers)
        return response

    middlewares = [make_cors_middleware(context.cors_config, SECURITY_HEADERS)]
    if context.rate_limiter is not None:
        middlewares.append(
            make_rate_limit_middleware(
                context.rate_limiter,
                WORKER_PORT_LOGGER,
                lambda request, ctx: client_ip,
            )
        )
    middlewares.append(make_validation_middleware(ALLOWED_METHODS, max_body_bytes))
    return build_chain(middlewares, terminal)


def _process_request(
    request: HttpRequest,
    context: WorkerContext,
    client_socket: socket.socket,
    client_ip: str,
    client_addr_str: str,
    max_body_bytes: int,
) -> bool:
    ctx = RequestContext(
        correlation_id=get_correlation_id(),
        start_ns=time.monotonic_ns(),
        request_wants_close=should_close(request.headers),
    )
    chain = _build_request_chain(context, client_ip, max_body_bytes)
    try:
        response = chain(request, ctx)
    except HttpError as error:
        response = ErrorMapper.to_response(error, request, context.cors_config)
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
        response = ErrorMapper.internal_error(request, context.cors_config)
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


def _max_body_bytes(context: WorkerContext) -> int:
    config = getattr(context, "config", None)
    limit = getattr(config, "max_body_bytes", DEFAULT_MAX_BODY_BYTES)
    return limit if isinstance(limit, int) else DEFAULT_MAX_BODY_BYTES


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


def _process_client_requests(
    client_socket: socket.socket,
    client_address: tuple[str, int],
    context: WorkerContext,
    lifecycle,
    client_ip: str,
    client_addr_str: str,
    max_body_bytes: int,
) -> None:
    buffer = b""
    while True:
        correlation_id = generate_correlation_id()
        set_correlation_id(correlation_id)

        try:
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
                max_body_bytes,
            )
            if should_terminate:
                break

            if request is None:
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
                client_ip,
                client_addr_str,
                max_body_bytes,
            )

            WORKER_LOGGER.debug(
                "Request processing complete",
                extra={"event": "request_complete", "client": client_addr_str},
            )

            if should_terminate_connection:
                break
        finally:
            clear_correlation_id()


def handle_client(
    client_socket: socket.socket,
    client_address: tuple[str, int],
    context: WorkerContext,
) -> None:
    """Process requests on a client socket until the connection is closed."""
    client_ip = client_address[0]
    current_thread = threading.current_thread()
    lifecycle = _prepare_worker(context, client_socket, current_thread)
    client_addr_str = format_client_address(client_address)
    max_body_bytes = _max_body_bytes(context)
    resources = _WorkerResources(
        current_thread, client_socket, client_ip, client_addr_str
    )

    try:
        _process_client_requests(
            client_socket,
            client_address,
            context,
            lifecycle,
            client_ip,
            client_addr_str,
            max_body_bytes,
        )
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

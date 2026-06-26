"""Worker thread logic for handling individual client connections."""

import socket
import threading
import time

from pyhttpd.adapters.logging.correlation_adapter import (
    clear_correlation_id,
    generate_correlation_id,
    get_correlation_id,
    set_correlation_id,
)
from pyhttpd.adapters.transport.context import WorkerContext
from pyhttpd.adapters.transport.io import send_response
from pyhttpd.adapters.transport.request_reader import (
    _read_request_with_validation,
    _recv_with_deadline,
)
from pyhttpd.adapters.transport.wire import format_client_address
from pyhttpd.adapters.transport.worker_lifecycle import (
    _cleanup_worker,
    _drain_if_requested,
    _max_body_bytes,
    _prepare_worker,
    _WorkerResources,
)
from pyhttpd.adapters.transport.worker_logging import (
    WORKER_LOGGER,
    WORKER_PORT_LOGGER,
    log_worker_error,
)
from pyhttpd.application.context import RequestContext
from pyhttpd.application.middleware.assembly import build_request_chain
from pyhttpd.application.rendering import ErrorMapper
from pyhttpd.application.routing import make_default_router
from pyhttpd.domain import HttpError, HttpRequest

__all__ = ["handle_client", "_recv_with_deadline"]


def _build_request_chain(context: WorkerContext, client_ip: str, max_body_bytes: int):
    """Assemble the application middleware chain over the default router."""
    router = make_default_router(
        context.directory,
        context.lifecycle,
        WORKER_PORT_LOGGER,
        context.cors_config,
        context.metrics_sink,
        context.file_options,
    )
    return build_request_chain(
        router.dispatch,
        cors_config=context.cors_config,
        metrics_sink=context.metrics_sink,
        rate_limiter=context.rate_limiter,
        authenticator=context.authenticator,
        logger=WORKER_PORT_LOGGER,
        client_ip=client_ip,
        max_body_bytes=max_body_bytes,
    )


def _apply_handler_timeout(
    client_socket: socket.socket, context: WorkerContext
) -> None:
    """Give the handler/write phase its own deadline, not the residual read one."""
    if context.phase_timeouts is not None:
        client_socket.settimeout(context.phase_timeouts.handler_seconds)
    elif context.config is not None:
        client_socket.settimeout(context.config.socket_timeout)


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
    )
    chain = _build_request_chain(context, client_ip, max_body_bytes)
    try:
        response = chain(request, ctx)
    except HttpError as error:
        response = ErrorMapper.to_response(error, request, context.cors_config)
    except Exception as error:  # pylint: disable=broad-except
        log_worker_error(error, client_addr_str)
        response = ErrorMapper.internal_error(request, context.cors_config)
    _apply_handler_timeout(client_socket, context)
    send_response(client_socket, response)
    return response.close_connection


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

            if context.config is not None:
                client_socket.settimeout(context.config.socket_timeout)
            request, buffer, should_terminate = _read_request_with_validation(
                client_socket,
                buffer,
                client_address,
                max_body_bytes,
                context.phase_timeouts,
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
        log_worker_error(error, client_addr_str)
    finally:
        _cleanup_worker(
            context,
            lifecycle,
            resources,
        )

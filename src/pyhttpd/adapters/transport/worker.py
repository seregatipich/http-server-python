"""Worker thread logic for handling individual client connections."""

import socket
import threading
import time
from dataclasses import replace

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
from pyhttpd.application.middleware.auth import make_auth_middleware
from pyhttpd.application.middleware.cors import make_cors_middleware
from pyhttpd.application.middleware.metrics import make_metrics_middleware
from pyhttpd.application.middleware.rate_limit import make_rate_limit_middleware
from pyhttpd.application.middleware.validation import make_validation_middleware
from pyhttpd.application.pipeline import build_chain
from pyhttpd.application.rendering import ErrorMapper
from pyhttpd.application.routing import make_default_router
from pyhttpd.domain import (
    ALLOWED_METHODS,
    SECURITY_HEADERS,
    HttpError,
    HttpRequest,
    HttpResponse,
)

__all__ = ["handle_client", "_recv_with_deadline"]


def _route_label(request: HttpRequest) -> str:
    """Collapse high-cardinality paths to bounded metric route labels."""
    if request.path.startswith("/echo/"):
        return "/echo/"
    if request.path.startswith("/files/"):
        return "/files/"
    return request.path


def _strip_body_for_head(response: HttpResponse) -> HttpResponse:
    """Return a HEAD response: same headers and length, no body."""
    length = response.content_length
    if length is None and not response.use_chunked:
        length = len(response.body)
    return replace(
        response,
        body=b"",
        body_iter=None,
        use_chunked=False,
        content_length=length,
    )


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

    def terminal(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        is_head = request.method == "HEAD"
        dispatch_request = replace(request, method="GET") if is_head else request
        try:
            response = router.dispatch(dispatch_request, ctx)
        except HttpError as error:
            response = ErrorMapper.to_response(error, request, context.cors_config)
        if is_head:
            response = _strip_body_for_head(response)
        if ctx.rate_decision is not None:
            response.headers.update(ctx.rate_decision.headers)
        return response

    middlewares = []
    if context.metrics_sink is not None:
        middlewares.append(make_metrics_middleware(context.metrics_sink, _route_label))
    middlewares.append(make_cors_middleware(context.cors_config, SECURITY_HEADERS))
    if context.rate_limiter is not None:
        middlewares.append(
            make_rate_limit_middleware(
                context.rate_limiter,
                WORKER_PORT_LOGGER,
                lambda request, ctx: client_ip,
                context.metrics_sink,
            )
        )
    middlewares.append(make_validation_middleware(ALLOWED_METHODS, max_body_bytes))
    if context.authenticator is not None:
        middlewares.append(
            make_auth_middleware(context.authenticator, WORKER_PORT_LOGGER)
        )
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
    )
    chain = _build_request_chain(context, client_ip, max_body_bytes)
    try:
        response = chain(request, ctx)
    except HttpError as error:
        response = ErrorMapper.to_response(error, request, context.cors_config)
    except Exception as error:  # pylint: disable=broad-except
        log_worker_error(error, client_addr_str)
        response = ErrorMapper.internal_error(request, context.cors_config)
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
        log_worker_error(error, client_addr_str)
    finally:
        _cleanup_worker(
            context,
            lifecycle,
            resources,
        )

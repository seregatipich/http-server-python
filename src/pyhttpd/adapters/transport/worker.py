"""Worker thread logic for handling individual client connections."""

import socket
import threading
import time

from pyhttpd.adapters.auth.client_cert import principal_from_peercert
from pyhttpd.adapters.http2 import Http2Connection
from pyhttpd.adapters.logging.correlation_adapter import (
    clear_correlation_id,
    generate_correlation_id,
    get_correlation_id,
    set_correlation_id,
)
from pyhttpd.adapters.tls import establish_tls
from pyhttpd.adapters.transport.chain_builder import build_worker_chain
from pyhttpd.adapters.transport.channel import SocketChannel
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
    log_worker_error,
)
from pyhttpd.application.context import RequestContext
from pyhttpd.application.rendering import ErrorMapper
from pyhttpd.domain import HttpError, HttpRequest, HttpResponse
from pyhttpd.domain.http2.frames import CONNECTION_PREFACE

__all__ = ["handle_client", "_recv_with_deadline"]


def _client_certificate_principal(client_socket: socket.socket, context: WorkerContext):
    """Map a verified mutual-TLS client certificate to a Principal, if enabled."""
    if context.client_cert_roles is None:
        return None
    getpeercert = getattr(client_socket, "getpeercert", None)
    if getpeercert is None:
        return None
    return principal_from_peercert(getpeercert(), context.client_cert_roles)


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
        error_format=context.error_format,
        client_principal=_client_certificate_principal(client_socket, context),
    )
    chain = build_worker_chain(context, client_ip, max_body_bytes)
    try:
        response = chain(request, ctx)
    except HttpError as error:
        response = ErrorMapper.to_response(
            error, request, context.cors_config, ctx.error_format, ctx.correlation_id
        )
    except Exception as error:  # pylint: disable=broad-except
        log_worker_error(error, client_addr_str)
        response = ErrorMapper.internal_error(
            request, context.cors_config, ctx.error_format, ctx.correlation_id
        )
    if response.upgrade is not None:
        return _perform_upgrade(client_socket, response, _upgrade_read_timeout(context))
    if not response.streaming:
        _apply_handler_timeout(client_socket, context)
    send_response(client_socket, response)
    if context.access_logger is not None:
        context.access_logger.record(client_ip, request, response)
    return response.close_connection


def _upgrade_read_timeout(context: WorkerContext) -> float | None:
    """Read/idle deadline for an upgraded (e.g. WebSocket) connection."""
    if context.config is not None:
        return context.config.socket_timeout
    return None


def _tls_handshake_timeout(context: WorkerContext) -> float | None:
    """Bound the per-connection TLS handshake so a silent peer cannot pin a worker."""
    if context.config is not None:
        return context.config.socket_timeout
    return None


def _perform_upgrade(
    client_socket: socket.socket,
    response: HttpResponse,
    read_timeout: float | None,
) -> bool:
    """Write the handshake headers verbatim, then hand the socket to the driver.

    Upgrade responses (101 Switching Protocols) carry no body and must not be
    reframed with Content-Length/Connection, so the handshake block is written
    directly. The socket keeps a finite read deadline so an idle or slow peer
    cannot pin the worker thread (and its connection slot) forever, and so a
    draining server can close the connection during graceful shutdown; the
    connection always closes when the driver returns.
    """
    header_lines = [response.status_line]
    header_lines.extend(f"{name}: {value}" for name, value in response.headers.items())
    client_socket.sendall("\r\n".join(header_lines).encode() + b"\r\n\r\n")
    client_socket.settimeout(read_timeout)
    assert response.upgrade is not None
    response.upgrade(SocketChannel(client_socket))
    return True


def _negotiate_protocol(
    client_socket: socket.socket, context: WorkerContext
) -> tuple[str, bytes]:
    """Return ("h2", seed) for HTTP/2 or ("http1", seed) otherwise."""
    if not context.enable_http2:
        return "http1", b""
    selected = getattr(client_socket, "selected_alpn_protocol", lambda: None)()
    if selected == "h2":
        return "h2", b""
    if selected is not None:
        return "http1", b""
    if context.config is not None:
        client_socket.settimeout(context.config.socket_timeout)
    seed = client_socket.recv(len(CONNECTION_PREFACE))
    return ("h2" if seed.startswith(b"PRI ") else "http1"), seed


def _run_http2(
    client_socket: socket.socket,
    seed: bytes,
    context: WorkerContext,
    client_ip: str,
    max_body_bytes: int,
) -> None:
    chain = build_worker_chain(context, client_ip, max_body_bytes)

    def make_context() -> RequestContext:
        set_correlation_id(generate_correlation_id())
        return RequestContext(
            correlation_id=get_correlation_id(),
            start_ns=time.monotonic_ns(),
            error_format=context.error_format,
            client_principal=_client_certificate_principal(client_socket, context),
        )

    Http2Connection(
        SocketChannel(client_socket), chain, make_context, max_body_bytes
    ).serve(seed)


def _process_client_requests(
    client_socket: socket.socket,
    client_address: tuple[str, int],
    context: WorkerContext,
    lifecycle,
    client_ip: str,
    client_addr_str: str,
    max_body_bytes: int,
    initial_buffer: bytes = b"",
) -> None:
    buffer = initial_buffer
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
                context.error_format,
                context.allow_chunked_requests,
                context.expect_continue,
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
        if context.tls_context is not None:
            client_socket = establish_tls(
                client_socket, context.tls_context, _tls_handshake_timeout(context)
            )
            resources.client_socket = client_socket
        protocol, seed = _negotiate_protocol(client_socket, context)
        if protocol == "h2":
            _run_http2(client_socket, seed, context, client_ip, max_body_bytes)
        else:
            _process_client_requests(
                client_socket,
                client_address,
                context,
                lifecycle,
                client_ip,
                client_addr_str,
                max_body_bytes,
                seed,
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

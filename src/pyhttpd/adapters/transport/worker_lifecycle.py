"""Per-connection worker lifecycle: setup, draining, and cleanup."""

import socket
import threading
from dataclasses import dataclass

from pyhttpd.adapters.logging.correlation_adapter import clear_correlation_id
from pyhttpd.adapters.transport.context import WorkerContext
from pyhttpd.adapters.transport.io import send_response
from pyhttpd.adapters.transport.worker_logging import WORKER_LOGGER
from pyhttpd.application.rendering import draining_response
from pyhttpd.domain import DEFAULT_MAX_BODY_BYTES, SECURITY_HEADERS


@dataclass
class _WorkerResources:
    thread: threading.Thread
    client_socket: socket.socket
    client_ip: str
    client_addr_str: str


def _prepare_worker(
    context: WorkerContext,
    client_socket: socket.socket,
    current_thread: threading.Thread,
):
    """Register the worker thread and apply the socket timeout."""
    lifecycle = context.lifecycle
    if lifecycle is not None:
        lifecycle.register_worker(current_thread)
    if context.config is not None:
        client_socket.settimeout(context.config.socket_timeout)
    return lifecycle


def _max_body_bytes(context: WorkerContext) -> int:
    """Resolve the configured maximum request body size."""
    config = getattr(context, "config", None)
    limit = getattr(config, "max_body_bytes", DEFAULT_MAX_BODY_BYTES)
    return limit if isinstance(limit, int) else DEFAULT_MAX_BODY_BYTES


def _drain_if_requested(lifecycle, client_socket: socket.socket) -> bool:
    """Send a draining response and signal termination when shutting down."""
    if lifecycle is None or not lifecycle.is_draining():
        return False
    send_response(client_socket, draining_response(SECURITY_HEADERS))
    return True


def _cleanup_worker(
    context: WorkerContext,
    lifecycle,
    resources: _WorkerResources,
):
    """Release connection slots, close the socket, and clear correlation state."""
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

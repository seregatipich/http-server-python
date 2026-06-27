"""Deadline-bounded socket reads shared by the request read paths."""

import socket
import time
from typing import Optional

from pyhttpd.domain import RequestTimeout


def _recv_with_deadline(client_socket: socket.socket, deadline_ns: int) -> bytes:
    """Receive data from socket with a deadline, raising RequestTimeout if exceeded."""
    remaining_ns = deadline_ns - time.monotonic_ns()
    if remaining_ns <= 0:
        raise RequestTimeout("Request deadline exceeded")
    client_socket.settimeout(remaining_ns / 1_000_000_000)
    try:
        return client_socket.recv(4096)
    except (socket.timeout, TimeoutError) as exc:
        raise RequestTimeout("Request deadline exceeded") from exc


def _deadline_ns(seconds: Optional[float]) -> Optional[int]:
    if seconds is None:
        return None
    return time.monotonic_ns() + int(seconds * 1_000_000_000)

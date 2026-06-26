"""HTTP Input/Output operations."""

import logging
import socket
import time
import urllib.parse
from typing import Optional, Tuple

from pyhttpd.adapters.logging.correlation_adapter import (
    CorrelationLoggerAdapter,
    get_correlation_id,
    set_correlation_id,
)
from pyhttpd.adapters.transport.wire import HEADER_DELIMITER
from pyhttpd.domain import (
    DEFAULT_MAX_BODY_BYTES,
    FILES_ENDPOINT_PREFIX,
    ForbiddenPath,
    HttpRequest,
    HttpResponse,
    PhaseTimeouts,
    RequestEntityTooLarge,
    RequestTimeout,
)

IO_LOGGER = CorrelationLoggerAdapter(logging.getLogger("http_server.io"), {})


def parse_headers(lines: list[str]) -> dict[str, str]:
    """Convert raw header lines into a lowercase-keyed dictionary."""
    parsed = {}
    for line in lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        normalized_name = name.strip().lower()
        if normalized_name:
            parsed[normalized_name] = value.lstrip(" \t")
    return parsed


def parse_request_line(request_line: str) -> Tuple[str, str]:
    """Parse the HTTP method and sanitized path from the request line."""
    try:
        method, target, _ = request_line.split(" ", 2)
    except ValueError as exc:
        raise ValueError("Invalid request line") from exc

    parsed_target = urllib.parse.urlsplit(target)
    path = urllib.parse.unquote(parsed_target.path)
    if (
        target.startswith(f"{FILES_ENDPOINT_PREFIX}..")
        or f"{FILES_ENDPOINT_PREFIX}../" in target
    ):
        raise ForbiddenPath
    return method, path


def _parse_content_length(header_value: str) -> int:
    try:
        content_length = int(header_value)
    except ValueError as exc:
        raise ValueError("Invalid Content-Length") from exc
    if content_length < 0:
        raise ValueError("Negative Content-Length")
    return content_length


def _enforce_body_size(content_length: int, max_body_bytes: int) -> None:
    if content_length > max_body_bytes:
        raise RequestEntityTooLarge


def determine_content_length(
    method: str,
    headers: dict[str, str],
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> int:
    """Validate and return the declared Content-Length for the request."""
    header_value = headers.get("content-length")
    if method == "POST" and header_value is None:
        raise ValueError("Missing Content-Length")
    if header_value is None:
        return 0
    content_length = _parse_content_length(header_value)
    _enforce_body_size(content_length, max_body_bytes)
    return content_length


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


def _read_until_headers(
    client_socket: socket.socket,
    buffer: bytes,
    timeouts: Optional[PhaseTimeouts] = None,
) -> bytes:
    deadline: Optional[int] = None
    while HEADER_DELIMITER not in buffer:
        if buffer and timeouts is not None:
            if deadline is None:
                deadline = time.monotonic_ns() + int(
                    timeouts.header_read_seconds * 1_000_000_000
                )
            chunk = _recv_with_deadline(client_socket, deadline)
        else:
            chunk = client_socket.recv(4096)
        if not chunk:
            return b""
        buffer += chunk
    return buffer


def _read_body(
    client_socket: socket.socket,
    remainder: bytes,
    content_length: int,
    max_body_bytes: int,
    timeouts: Optional[PhaseTimeouts] = None,
) -> Tuple[Optional[bytes], bytes]:
    deadline = (
        _deadline_ns(timeouts.body_read_seconds) if timeouts is not None else None
    )
    while len(remainder) < content_length:
        if deadline is not None:
            chunk = _recv_with_deadline(client_socket, deadline)
        else:
            chunk = client_socket.recv(4096)
        if not chunk:
            return None, b""
        remainder += chunk
        if len(remainder) > max_body_bytes:
            raise RequestEntityTooLarge
    return remainder[:content_length], remainder[content_length:]


def receive_request(
    client_socket: socket.socket,
    buffer: bytes,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    timeouts: Optional[PhaseTimeouts] = None,
) -> Tuple[Optional[HttpRequest], bytes]:
    """Read bytes from the socket until a complete request is available."""
    buffer = _read_until_headers(client_socket, buffer, timeouts)
    if not buffer:
        return None, b""

    header_block, remainder = buffer.split(HEADER_DELIMITER, 1)
    header_lines = header_block.decode().split("\r\n")
    method, path = parse_request_line(header_lines[0])
    headers = parse_headers(header_lines[1:])

    incoming_correlation_id = headers.get("x-request-id")
    if incoming_correlation_id:
        set_correlation_id(incoming_correlation_id)

    content_length = determine_content_length(method, headers, max_body_bytes)
    body, leftover = _read_body(
        client_socket, remainder, content_length, max_body_bytes, timeouts
    )
    if body is None:
        return None, b""
    IO_LOGGER.debug("Parsed request", extra={"method": method, "path": path})
    return HttpRequest(method, path, headers, body), leftover


def _response_headers(response: HttpResponse) -> dict[str, str]:
    headers = dict(response.headers)
    correlation_id = get_correlation_id()
    if correlation_id:
        headers["X-Request-ID"] = correlation_id
    if response.use_chunked:
        headers["Transfer-Encoding"] = "chunked"
    elif response.content_length is not None:
        headers["Content-Length"] = str(response.content_length)
    else:
        headers["Content-Length"] = str(len(response.body))
    if response.close_connection:
        headers["Connection"] = "close"
    return headers


def _header_block(status_line: str, headers: dict[str, str]) -> bytes:
    header_lines = [status_line]
    header_lines.extend(f"{name}: {value}" for name, value in headers.items())
    return "\r\n".join(header_lines).encode() + b"\r\n\r\n"


def _send_chunked_response(
    client_socket: socket.socket,
    header_block: bytes,
    response: HttpResponse,
) -> None:
    client_socket.sendall(header_block)
    for chunk in response.body_iter or ():
        if not chunk:
            continue
        size_line = f"{len(chunk):X}\r\n".encode()
        client_socket.sendall(size_line)
        client_socket.sendall(chunk)
        client_socket.sendall(b"\r\n")
    client_socket.sendall(b"0\r\n\r\n")


def send_response(client_socket: socket.socket, response: HttpResponse) -> None:
    """Serialize and send the HTTP response over the socket."""
    header_block = _header_block(response.status_line, _response_headers(response))
    if response.use_chunked and response.body_iter is not None:
        _send_chunked_response(client_socket, header_block, response)
    elif response.body_iter is not None:
        client_socket.sendall(header_block)
        for chunk in response.body_iter:
            if chunk:
                client_socket.sendall(chunk)
    else:
        client_socket.sendall(header_block + response.body)
    IO_LOGGER.debug(
        "Sent response",
        extra={"status": response.status_line, "use_chunked": response.use_chunked},
    )

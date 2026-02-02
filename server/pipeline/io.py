"""HTTP Input/Output operations."""

import logging
import socket
import urllib.parse
from typing import Optional, Tuple

from server.bootstrap.config import FILES_ENDPOINT_PREFIX, HEADER_DELIMITER, MAX_BODY_BYTES
from server.domain.correlation_id import (
    CorrelationLoggerAdapter,
    get_correlation_id,
    set_correlation_id,
)
from server.domain.http_types import HttpRequest, HttpResponse
from server.domain.sandbox import ForbiddenPath
from server.pipeline.validation import RequestEntityTooLarge

IO_LOGGER = CorrelationLoggerAdapter(logging.getLogger("http_server.io"), {})


def parse_headers(lines: list[str]) -> dict[str, str]:
    """Convert raw header lines into a lowercase-keyed dictionary."""
    parsed = {}
    for line in lines:
        if ": " in line:
            name, value = line.split(": ", 1)
            parsed[name.lower()] = value
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


def determine_content_length(method: str, headers: dict[str, str]) -> int:
    """Validate and return the declared Content-Length for the request."""
    header_value = headers.get("content-length")
    if method == "POST" and header_value is None:
        raise ValueError("Missing Content-Length")
    if header_value is None:
        return 0
    try:
        content_length = int(header_value)
    except ValueError as exc:
        raise ValueError("Invalid Content-Length") from exc
    if content_length < 0:
        raise ValueError("Negative Content-Length")
    if content_length > MAX_BODY_BYTES:
        raise RequestEntityTooLarge
    return content_length


def receive_request(
    client_socket: socket.socket, buffer: bytes
) -> Tuple[Optional[HttpRequest], bytes]:
    """Read bytes from the socket until a complete request is available."""
    while HEADER_DELIMITER not in buffer:
        chunk = client_socket.recv(4096)
        if not chunk:
            return None, b""
        buffer += chunk

    header_block, remainder = buffer.split(HEADER_DELIMITER, 1)
    header_lines = header_block.decode().split("\r\n")
    method, path = parse_request_line(header_lines[0])
    headers = parse_headers(header_lines[1:])

    incoming_correlation_id = headers.get("x-request-id")
    if incoming_correlation_id:
        set_correlation_id(incoming_correlation_id)

    content_length = determine_content_length(method, headers)

    while len(remainder) < content_length:
        chunk = client_socket.recv(4096)
        if not chunk:
            return None, b""
        remainder += chunk
        if len(remainder) > MAX_BODY_BYTES:
            raise RequestEntityTooLarge

    body = remainder[:content_length]
    leftover = remainder[content_length:]
    IO_LOGGER.debug("Parsed request", extra={"method": method, "path": path})
    return HttpRequest(method, path, headers, body), leftover


def send_response(client_socket: socket.socket, response: HttpResponse) -> None:
    """Serialize and send the HTTP response over the socket."""
    headers = dict(response.headers)

    correlation_id = get_correlation_id()
    if correlation_id:
        headers["X-Request-ID"] = correlation_id

    if response.use_chunked:
        headers["Transfer-Encoding"] = "chunked"
    else:
        headers["Content-Length"] = str(len(response.body))
    if response.close_connection:
        headers["Connection"] = "close"
    header_lines = [response.status_line]
    header_lines.extend(f"{name}: {value}" for name, value in headers.items())
    header_block = "\r\n".join(header_lines).encode() + b"\r\n\r\n"
    if response.use_chunked and response.body_iter is not None:
        client_socket.sendall(header_block)
        for chunk in response.body_iter:
            if not chunk:
                continue
            size_line = f"{len(chunk):X}\r\n".encode()
            client_socket.sendall(size_line)
            client_socket.sendall(chunk)
            client_socket.sendall(b"\r\n")
        client_socket.sendall(b"0\r\n\r\n")
    else:
        client_socket.sendall(header_block + response.body)
    IO_LOGGER.debug(
        "Sent response",
        extra={"status": response.status_line, "use_chunked": response.use_chunked},
    )

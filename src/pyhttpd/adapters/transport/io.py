"""HTTP Input/Output operations."""

import logging
import socket
import ssl
import time
import urllib.parse
from typing import NamedTuple, Optional, Tuple

from pyhttpd.adapters.logging.correlation_adapter import (
    CorrelationLoggerAdapter,
    get_correlation_id,
    set_correlation_id,
)
from pyhttpd.adapters.transport.chunked_reader import read_chunked_body
from pyhttpd.adapters.transport.deadline import _deadline_ns, _recv_with_deadline
from pyhttpd.adapters.transport.wire import HEADER_DELIMITER
from pyhttpd.domain import (
    DEFAULT_MAX_BODY_BYTES,
    FILES_ENDPOINT_PREFIX,
    ForbiddenPath,
    HttpRequest,
    HttpResponse,
    PhaseTimeouts,
    RequestEntityTooLarge,
)

_CONTINUE_RESPONSE = b"HTTP/1.1 100 Continue\r\n\r\n"

IO_LOGGER = CorrelationLoggerAdapter(logging.getLogger("http_server.io"), {})

# Cap the request header block so a client streaming headers without a
# terminating blank line cannot exhaust memory; 64 KiB is generous for
# legitimate cookies and authorization headers.
MAX_HEADER_BYTES = 64 * 1024


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


_SUPPORTED_HTTP_VERSIONS = ("HTTP/1.0", "HTTP/1.1")
_HEADER_CONTROL_CHARS = ("\x00", "\r", "\n")


def parse_request_line(request_line: str) -> Tuple[str, str, str]:
    """Parse the HTTP method, sanitized path, and raw query from the request line."""
    try:
        method, target, version = request_line.split(" ", 2)
    except ValueError as exc:
        raise ValueError("Invalid request line") from exc

    if version not in _SUPPORTED_HTTP_VERSIONS:
        raise ValueError("Unsupported HTTP version")

    parsed_target = urllib.parse.urlsplit(target)
    path = urllib.parse.unquote(parsed_target.path)
    if (
        target.startswith(f"{FILES_ENDPOINT_PREFIX}..")
        or f"{FILES_ENDPOINT_PREFIX}../" in target
    ):
        raise ForbiddenPath
    return method, path, parsed_target.query


def _parse_content_length(header_value: str) -> int:
    text = header_value.strip()
    if not (text.isascii() and text.isdigit()):
        raise ValueError("Invalid Content-Length")
    return int(text)


def _enforce_body_size(content_length: int, max_body_bytes: int) -> None:
    if content_length > max_body_bytes:
        raise RequestEntityTooLarge


def _header_values(header_lines: list[str], name: str) -> list[str]:
    return [
        line.split(":", 1)[1].strip()
        for line in header_lines
        if ":" in line and line.split(":", 1)[0].strip().lower() == name
    ]


def _reject_ambiguous_framing(
    header_lines: list[str],
    allow_chunked: bool = False,
) -> bool:
    """Reject ambiguous request framing and report whether the body is chunked.

    The body is framed solely by Content-Length, so a Transfer-Encoding header
    (which an upstream proxy might honor instead) or conflicting Content-Length
    values would desynchronize framing -- a request-smuggling vector
    (RFC 9112 section 6.3). When chunked requests are explicitly enabled, a
    single final ``chunked`` coding is accepted, but Transfer-Encoding combined
    with Content-Length, duplicated, or stacked with other codings is still
    rejected.
    """
    transfer_encodings = _header_values(header_lines, "transfer-encoding")
    content_lengths = set(_header_values(header_lines, "content-length"))
    if transfer_encodings:
        if not allow_chunked:
            raise ValueError("Transfer-Encoding is not supported")
        if len(transfer_encodings) > 1:
            raise ValueError("multiple Transfer-Encoding headers")
        codings = [
            c.strip().lower() for c in transfer_encodings[0].split(",") if c.strip()
        ]
        if codings != ["chunked"]:
            raise ValueError("unsupported Transfer-Encoding coding")
        if content_lengths:
            raise ValueError("Transfer-Encoding combined with Content-Length")
        return True
    if len(content_lengths) > 1:
        raise ValueError("conflicting Content-Length headers")
    return False


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
        if len(buffer) > MAX_HEADER_BYTES:
            raise RequestEntityTooLarge
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


def _wants_continue(headers: dict[str, str], expect_continue: bool) -> bool:
    return (
        expect_continue and headers.get("expect", "").strip().lower() == "100-continue"
    )


def _read_request_body(
    client_socket: socket.socket,
    remainder: bytes,
    method: str,
    headers: dict[str, str],
    *,
    is_chunked: bool,
    max_body_bytes: int,
    timeouts: Optional[PhaseTimeouts],
    expect_continue: bool,
) -> Tuple[Optional[bytes], bytes]:
    if is_chunked:
        # A chunked body has no declared size to pre-validate, so 100 Continue is
        # sent unconditionally; the decoder still caps the body at max_body_bytes.
        # The Content-Length path below validates the declared size first, so the
        # two paths are intentionally asymmetric -- do not "align" them by moving
        # this send after the decoder, which would break the Expect handshake.
        if _wants_continue(headers, expect_continue):
            client_socket.sendall(_CONTINUE_RESPONSE)
        return read_chunked_body(client_socket, remainder, max_body_bytes, timeouts)
    content_length = determine_content_length(method, headers, max_body_bytes)
    if content_length > 0 and _wants_continue(headers, expect_continue):
        client_socket.sendall(_CONTINUE_RESPONSE)
    return _read_body(
        client_socket, remainder, content_length, max_body_bytes, timeouts
    )


class _RequestHead(NamedTuple):
    method: str
    path: str
    query: str
    raw_path: str
    headers: dict[str, str]
    is_chunked: bool
    remainder: bytes


def _reject_malformed_header_lines(header_lines: list[str]) -> None:
    """Reject obs-fold, whitespace-before-colon, and embedded control characters.

    Lines are already split on CRLF, so any remaining CR/LF is a bare control
    byte that a discrepant downstream could re-frame (response splitting); an
    obs-fold continuation or whitespace before the colon are RFC 9112 5.1/5.2
    MUST-violations that enable request smuggling.
    """
    for line in header_lines:
        if any(control in line for control in _HEADER_CONTROL_CHARS):
            raise ValueError("control character in header line")
    for line in header_lines[1:]:
        if line[:1] in (" ", "\t"):
            raise ValueError("obs-fold continuation is not allowed")
        if ":" in line:
            name = line.split(":", 1)[0]
            if name.strip() and name != name.rstrip():
                raise ValueError("whitespace before header colon")


def _validate_host(request_line: str, header_lines: list[str]) -> None:
    """Enforce a single Host header (required on HTTP/1.1) per RFC 9112 3.2."""
    hosts = _header_values(header_lines, "host")
    if len(hosts) > 1:
        raise ValueError("multiple Host headers")
    if request_line.endswith("HTTP/1.1") and not hosts:
        raise ValueError("missing Host header")


def _parse_request_head(buffer: bytes, allow_chunked: bool) -> _RequestHead:
    header_block, remainder = buffer.split(HEADER_DELIMITER, 1)
    header_lines = header_block.decode().split("\r\n")
    _reject_malformed_header_lines(header_lines)
    method, path, query = parse_request_line(header_lines[0])
    _validate_host(header_lines[0], header_lines[1:])
    raw_path = urllib.parse.urlsplit(header_lines[0].split(" ", 2)[1]).path
    headers = parse_headers(header_lines[1:])
    is_chunked = _reject_ambiguous_framing(header_lines[1:], allow_chunked)
    return _RequestHead(method, path, query, raw_path, headers, is_chunked, remainder)


def _propagate_correlation_id(headers: dict[str, str]) -> None:
    incoming_correlation_id = headers.get("x-request-id")
    if incoming_correlation_id and not any(
        control in incoming_correlation_id for control in _HEADER_CONTROL_CHARS
    ):
        set_correlation_id(incoming_correlation_id)


def receive_request(
    client_socket: socket.socket,
    buffer: bytes,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    timeouts: Optional[PhaseTimeouts] = None,
    *,
    allow_chunked: bool = False,
    expect_continue: bool = False,
) -> Tuple[Optional[HttpRequest], bytes]:
    """Read bytes from the socket until a complete request is available."""
    buffer = _read_until_headers(client_socket, buffer, timeouts)
    if not buffer:
        return None, b""

    head = _parse_request_head(buffer, allow_chunked)
    _propagate_correlation_id(head.headers)
    body, leftover = _read_request_body(
        client_socket,
        head.remainder,
        head.method,
        head.headers,
        is_chunked=head.is_chunked,
        max_body_bytes=max_body_bytes,
        timeouts=timeouts,
        expect_continue=expect_continue,
    )
    if body is None:
        return None, b""
    IO_LOGGER.debug("Parsed request", extra={"method": head.method, "path": head.path})
    return (
        HttpRequest(
            head.method, head.path, head.headers, body, head.query, head.raw_path
        ),
        leftover,
    )


def _response_headers(response: HttpResponse, is_tls: bool = True) -> dict[str, str]:
    headers = dict(response.headers)
    if not is_tls:
        # RFC 6797 7.2: HSTS MUST NOT be advertised over a non-secure transport.
        headers.pop("Strict-Transport-Security", None)
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
    is_tls = isinstance(client_socket, ssl.SSLSocket)
    header_block = _header_block(
        response.status_line, _response_headers(response, is_tls)
    )
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

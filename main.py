"""HTTP server supporting echo, user-agent, and file operations."""

import argparse
import gzip
import logging
import os
import socket
import ssl
import sys
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional, Tuple

from limits import (
    ConnectionLimiter,
    RateLimitDecision,
    TokenBucketLimiter,
    TokenBucketSettings,
)
from logging_config import configure_logging

SERVER_LOGGER = logging.getLogger("http_server.server")
COMPRESSION_LOGGER = logging.getLogger("http_server.compression")

HEADER_DELIMITER = b"\r\n\r\n"
FILES_ENDPOINT_PREFIX = "/files/"
ALLOWED_METHODS = {"GET", "POST"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value is not None else default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


MAX_BODY_BYTES = _env_int("HTTP_SERVER_MAX_BODY_BYTES", 5 * 1024 * 1024)
DEFAULT_MAX_CONNECTIONS = _env_int("HTTP_SERVER_MAX_CONNECTIONS", 200)
DEFAULT_MAX_CONNECTIONS_PER_IP = _env_int("HTTP_SERVER_MAX_CONNECTIONS_PER_IP", 20)
DEFAULT_RATE_LIMIT = _env_int("HTTP_SERVER_RATE_LIMIT", 50)
DEFAULT_RATE_WINDOW_MS = _env_int("HTTP_SERVER_RATE_WINDOW_MS", 10_000)
DEFAULT_BURST_CAPACITY = _env_int("HTTP_SERVER_BURST_CAPACITY", 25)
DEFAULT_RATE_LIMIT_DRY_RUN = _env_bool("HTTP_SERVER_RATE_LIMIT_DRY_RUN", False)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
}


class ForbiddenPath(Exception):
    """Raised when a requested path escapes the configured sandbox."""


class RequestEntityTooLarge(Exception):
    """Raised when a request body exceeds configured limits."""


@dataclass
class HttpRequest:
    """Represents a parsed HTTP request."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass
class HttpResponse:
    """Represents an HTTP response to be sent to a client."""

    status_line: str
    headers: dict[str, str]
    body: bytes
    close_connection: bool
    body_iter: Optional[Iterable[bytes]] = None
    use_chunked: bool = False


def handle_client(
    client_socket: socket.socket,
    directory: str,
    client_address: tuple[str, int],
    connection_limiter: Optional[ConnectionLimiter] = None,
    rate_limiter: Optional[TokenBucketLimiter] = None,
) -> None:
    """Process requests on a client socket until the connection is closed."""
    buffer = b""
    client_ip = client_address[0]
    SERVER_LOGGER.debug("Connection opened", extra={"client": client_address})
    try:
        while True:
            request, buffer, should_terminate = _read_request_with_validation(
                client_socket,
                buffer,
                client_address,
            )
            if should_terminate:
                break

            rate_decision: Optional[RateLimitDecision] = None
            if rate_limiter is not None and request is not None:
                rate_decision = rate_limiter.consume(client_ip)
                if not rate_decision.allowed and not rate_decision.dry_run:
                    SERVER_LOGGER.warning(
                        "Rate limit exceeded",
                        extra={
                            "client": client_address,
                            "limit_type": "ip",
                            "limit": rate_decision.limit,
                        },
                    )
                    send_response(
                        client_socket,
                        rate_limited_response(rate_decision, request),
                    )
                    break

            if request is None:
                continue

            validation_response = validate_request(request)
            if validation_response is not None:
                send_response(client_socket, validation_response)
                if validation_response.close_connection:
                    break
                continue

            response = build_response(request, directory)
            if rate_decision is not None:
                response.headers.update(rate_decision.headers)
            send_response(client_socket, response)
            if response.close_connection:
                break
    except (
        ConnectionError,
        TimeoutError,
        OSError,
        UnicodeDecodeError,
    ):
        SERVER_LOGGER.exception(
            "Error handling client", extra={"client": client_address}
        )
    finally:
        if connection_limiter is not None:
            connection_limiter.release(client_ip)
        client_socket.close()
        SERVER_LOGGER.debug("Connection closed", extra={"client": client_address})


def _read_request_with_validation(
    client_socket: socket.socket,
    buffer: bytes,
    client_address: tuple[str, int],
) -> tuple[Optional[HttpRequest], bytes, bool]:
    """Read a request from the socket while enforcing size and path limits."""

    try:
        request, buffer = receive_request(client_socket, buffer)
    except RequestEntityTooLarge:
        SERVER_LOGGER.warning("Request body too large", extra={"client": client_address})
        send_response(client_socket, entity_too_large_response())
        return None, b"", True
    except ForbiddenPath:
        SERVER_LOGGER.warning("Forbidden path", extra={"client": client_address})
        send_response(client_socket, forbidden_response())
        return None, b"", True
    except ValueError:
        SERVER_LOGGER.warning("Malformed request", extra={"client": client_address})
        send_response(client_socket, bad_request_response())
        return None, b"", True

    if request is None:
        SERVER_LOGGER.debug("Client disconnected", extra={"client": client_address})
        return None, buffer, True
    return request, buffer, False


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
    SERVER_LOGGER.debug("Parsed request", extra={"method": method, "path": path})
    return HttpRequest(method, path, headers, body), leftover


def parse_headers(lines: Iterable[str]) -> dict[str, str]:
    """Convert raw header lines into a lowercase-keyed dictionary."""
    parsed = {}
    for line in lines:
        if ": " in line:
            name, value = line.split(": ", 1)
            parsed[name.lower()] = value
    return parsed


def enforce_allowed_method(request: HttpRequest) -> Optional[HttpResponse]:
    """Ensure the HTTP method is part of the supported allowlist."""
    if request.method in ALLOWED_METHODS:
        return None
    return method_not_allowed_response(request)


def enforce_safe_path(request: HttpRequest) -> Optional[HttpResponse]:
    """Validate that the path conforms to sandbox safety requirements."""
    if not request.path.startswith("/") or "\x00" in request.path:
        return bad_request_response(request)
    if "/../" in request.path or request.path.endswith("/..") or request.path.startswith("/.."):
        return forbidden_response(request)
    return None


def enforce_post_constraints(request: HttpRequest) -> Optional[HttpResponse]:
    """Validate POST-specific invariants such as Content-Length and size."""
    declared_length = request.headers.get("content-length")
    if declared_length is None:
        return bad_request_response(request)
    try:
        content_length = int(declared_length)
    except ValueError:
        return bad_request_response(request)
    if content_length != len(request.body):
        return bad_request_response(request)
    if content_length > MAX_BODY_BYTES:
        return entity_too_large_response()
    return None


def parse_request_line(request_line: str) -> Tuple[str, str]:
    """Parse the HTTP method and sanitized path from the request line."""
    try:
        method, target, _ = request_line.split(" ", 2)
    except ValueError as exc:
        raise ValueError("Invalid request line") from exc

    parsed_target = urllib.parse.urlsplit(target)
    path = urllib.parse.unquote(parsed_target.path)
    if target.startswith(f"{FILES_ENDPOINT_PREFIX}..") or f"{FILES_ENDPOINT_PREFIX}../" in target:
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


def validate_request(request: HttpRequest) -> Optional[HttpResponse]:
    """Return an error response when the request fails validation checks."""
    method_error = enforce_allowed_method(request)
    if method_error is not None:
        return method_error

    path_error = enforce_safe_path(request)
    if path_error is not None:
        return path_error

    if request.method != "POST":
        return None

    return enforce_post_constraints(request)


def resolve_sandbox_path(directory: str, user_path: str) -> Path:
    """Resolve a user-supplied path inside the configured sandbox."""
    if "\x00" in user_path:
        raise ForbiddenPath

    directory_root = Path(directory).resolve()
    relative_part = user_path.lstrip("/")
    if not relative_part:
        raise ForbiddenPath

    if ".." in Path(relative_part).parts:
        raise ForbiddenPath

    target = (directory_root / relative_part).resolve()
    if not (target == directory_root or directory_root in target.parents):
        raise ForbiddenPath

    return target


def build_response(request: HttpRequest, directory: str) -> HttpResponse:
    """Route the request to the appropriate handler and return a response."""
    response = not_found_response(request)
    if request.path == "/":
        response = empty_response(request)
    elif request.path.startswith("/echo/"):
        response = text_response(request.path[6:], request)
    elif request.path == "/user-agent":
        agent = request.headers.get("user-agent", "")
        response = text_response(agent, request)
    elif request.path.startswith(FILES_ENDPOINT_PREFIX):
        remainder = request.path[len(FILES_ENDPOINT_PREFIX) :]
        is_invalid = (
            not remainder
            or remainder.startswith("../")
            or "/../" in remainder
            or remainder.startswith("..")
        )
        response = (
            forbidden_response(request)
            if is_invalid
            else file_response(request, directory)
        )
    return response


def empty_response(request: HttpRequest) -> HttpResponse:
    """Return a 200 OK response with no body."""
    return HttpResponse(
        "HTTP/1.1 200 OK", SECURITY_HEADERS.copy(), b"", should_close(request.headers)
    )


def text_response(message: str, request: HttpRequest) -> HttpResponse:
    """Return a text/plain response, compressing when appropriate."""
    payload = message.encode()
    payload, headers = compress_if_gzip_supported(payload, request.headers)
    base_headers = {"Content-Type": "text/plain", **headers, **SECURITY_HEADERS}
    return HttpResponse(
        "HTTP/1.1 200 OK", base_headers, payload, should_close(request.headers)
    )


def file_response(request: HttpRequest, directory: str) -> HttpResponse:
    """Serve or write a file based on the HTTP method."""
    filename = request.path[len(FILES_ENDPOINT_PREFIX) :]
    try:
        resolved_path = resolve_sandbox_path(directory, filename)
    except ForbiddenPath:
        SERVER_LOGGER.warning(
            "Forbidden path",
            extra={"path": filename, "method": request.method},
        )
        return forbidden_response(request)

    if request.method == "GET":
        if resolved_path.exists() and resolved_path.is_file():
            headers = {
                "Content-Type": "application/octet-stream",
                **SECURITY_HEADERS,
            }
            SERVER_LOGGER.info(
                "Served file",
                extra={"path": resolved_path.as_posix(), "method": request.method},
            )
            return HttpResponse(
                "HTTP/1.1 200 OK",
                headers,
                b"",
                should_close(request.headers),
                body_iter=stream_file(resolved_path),
                use_chunked=True,
            )
        return not_found_response(request)
    if request.method == "POST":
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        with open(resolved_path, "wb") as file_handle:
            file_handle.write(request.body)
        SERVER_LOGGER.info(
            "Stored file",
            extra={"path": resolved_path.as_posix(), "method": request.method},
        )
        return HttpResponse(
            "HTTP/1.1 201 Created",
            SECURITY_HEADERS.copy(),
            b"",
            should_close(request.headers),
        )
    if resolved_path.is_dir():
        return forbidden_response(request)
    SERVER_LOGGER.warning(
        "Unsupported method",
        extra={"path": resolved_path.as_posix(), "method": request.method},
    )
    return method_not_allowed_response(request)


def stream_file(filepath: Path, chunk_size: int = 65536) -> Iterator[bytes]:
    """Yield file contents in fixed-size chunks for streaming responses."""
    with open(filepath, "rb") as file_handle:
        while True:
            chunk = file_handle.read(chunk_size)
            if not chunk:
                break
            yield chunk


def not_found_response(request: HttpRequest) -> HttpResponse:
    """Return a 404 response reusing the connection preference."""
    return HttpResponse(
        "HTTP/1.1 404 Not Found",
        SECURITY_HEADERS.copy(),
        b"",
        should_close(request.headers),
    )


def forbidden_response(request: Optional[HttpRequest] = None) -> HttpResponse:
    """Produce a 403 response honoring the caller's connection preference."""
    headers = request.headers if request is not None else {}
    return HttpResponse(
        "HTTP/1.1 403 Forbidden",
        SECURITY_HEADERS.copy(),
        b"",
        should_close(headers) if request is not None else True,
    )


def bad_request_response(request: Optional[HttpRequest] = None) -> HttpResponse:
    """Produce a 400 response honoring the caller's connection preference."""
    headers = request.headers if request is not None else {}
    return HttpResponse(
        "HTTP/1.1 400 Bad Request",
        SECURITY_HEADERS.copy(),
        b"",
        should_close(headers) if request is not None else True,
    )


def entity_too_large_response() -> HttpResponse:
    """Produce a 413 response that always closes the connection."""
    return HttpResponse("HTTP/1.1 413 Payload Too Large", SECURITY_HEADERS.copy(), b"", True)


def rate_limited_response(decision: RateLimitDecision, request: HttpRequest) -> HttpResponse:
    """Create a 429 response populated with RateLimit headers."""
    retry_after = max(1, int(decision.reset_seconds)) if decision.reset_seconds else 1
    headers = {"Retry-After": str(retry_after), **decision.headers, **SECURITY_HEADERS}
    body = b"Rate limit exceeded"
    return HttpResponse(
        "HTTP/1.1 429 Too Many Requests",
        headers,
        body,
        should_close(request.headers),
    )


def connection_limited_response(limit_type: str | None) -> HttpResponse:
    """Produce a 503 response describing which connection quota was exceeded."""
    reason = "Connection limit exceeded"
    if limit_type:
        reason = f"{limit_type} connection limit exceeded"
    headers = {"Retry-After": "1", **SECURITY_HEADERS}
    return HttpResponse(
        "HTTP/1.1 503 Service Unavailable",
        headers,
        reason.encode(),
        True,
    )


def method_not_allowed_response(request: HttpRequest) -> HttpResponse:
    """Produce a 405 response enumerating the supported HTTP methods."""
    allow_header = ", ".join(sorted(ALLOWED_METHODS))
    headers = {"Allow": allow_header, **SECURITY_HEADERS}
    return HttpResponse(
        "HTTP/1.1 405 Method Not Allowed",
        headers,
        b"",
        should_close(request.headers),
    )


def compress_if_gzip_supported(
    payload: bytes, headers: dict[str, str]
) -> Tuple[bytes, dict[str, str]]:
    """Compress the payload when the request advertises gzip support."""
    if not accepts_gzip(headers):
        return payload, {}
    COMPRESSION_LOGGER.debug("Compressed payload", extra={"size": len(payload)})
    return gzip.compress(payload), {"Content-Encoding": "gzip"}


def accepts_gzip(headers: dict[str, str]) -> bool:
    """Return True when the Accept-Encoding header includes gzip with q>0."""
    encodings = headers.get("accept-encoding", "")
    for token in encodings.split(","):
        value = token.strip()
        if not value:
            continue
        algorithm, _, params = value.partition(";")
        if algorithm.strip().lower() != "gzip":
            continue
        quality = 1.0
        if params:
            for param in params.split(";"):
                key, _, raw_value = param.strip().partition("=")
                if key.lower() == "q" and raw_value:
                    try:
                        quality = float(raw_value)
                    except ValueError:
                        quality = 0.0
                    break
        if quality > 0:
            return True
    return False


def should_close(headers: dict[str, str]) -> bool:
    """Determine whether the connection should be closed after responding."""
    return headers.get("connection", "").lower() == "close"


def send_response(client_socket: socket.socket, response: HttpResponse) -> None:
    """Serialize and send the HTTP response over the socket."""
    headers = dict(response.headers)
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
    SERVER_LOGGER.debug(
        "Sent response",
        extra={"status": response.status_line, "use_chunked": response.use_chunked},
    )


def parse_cli_args(argv: list[str]) -> argparse.Namespace:
    """Return parsed CLI arguments for server configuration."""
    parser = argparse.ArgumentParser(description="HTTP server configuration")
    parser.add_argument("--directory", default=".")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=4221)
    parser.add_argument("--cert", help="Path to TLS certificate file")
    parser.add_argument("--key", help="Path to TLS private key file")
    default_log_level = os.getenv("HTTP_SERVER_LOG_LEVEL", "INFO").upper()
    default_destination = os.getenv("HTTP_SERVER_LOG_DESTINATION", "stdout")
    parser.add_argument(
        "--log-level",
        default=default_log_level,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        type=str.upper,
    )
    parser.add_argument(
        "--log-destination",
        default=default_destination,
        help="stdout or a file path",
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=DEFAULT_MAX_CONNECTIONS,
        help="Maximum concurrent connections (0 for unlimited)",
    )
    parser.add_argument(
        "--max-connections-per-ip",
        type=int,
        default=DEFAULT_MAX_CONNECTIONS_PER_IP,
        help="Maximum concurrent connections per client IP (0 for unlimited)",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=DEFAULT_RATE_LIMIT,
        help="Requests allowed per rate window (0 to disable)",
    )
    parser.add_argument(
        "--rate-window-ms",
        type=int,
        default=DEFAULT_RATE_WINDOW_MS,
        help="Rate limit window in milliseconds",
    )
    parser.add_argument(
        "--burst-capacity",
        type=int,
        default=DEFAULT_BURST_CAPACITY,
        help="Token bucket capacity for bursts",
    )
    parser.add_argument(
        "--rate-limit-dry-run",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_RATE_LIMIT_DRY_RUN,
        help="Log rate limit breaches without enforcing",
    )
    return parser.parse_args(argv)


def main() -> None:
    """Start the HTTP server and spawn worker threads per connection."""
    args = parse_cli_args(sys.argv[1:])
    configure_logging(args.log_level, args.log_destination)
    SERVER_LOGGER.info(
        "Starting HTTP server",
        extra={
            "host": args.host,
            "port": args.port,
            "directory": args.directory,
            "log_destination": args.log_destination,
            "log_level": args.log_level,
            "tls": bool(args.cert and args.key),
        },
    )
    server_socket = socket.create_server((args.host, args.port), reuse_port=True)
    if args.cert and args.key:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(args.cert, args.key)
            server_socket = context.wrap_socket(server_socket, server_side=True)
        except ssl.SSLError as e:
            SERVER_LOGGER.critical("Failed to load TLS certificates", extra={"error": str(e)})
            sys.exit(1)

    connection_limiter = ConnectionLimiter(
        args.max_connections,
        args.max_connections_per_ip,
    )
    rate_limiter: Optional[TokenBucketLimiter] = None
    if args.rate_limit > 0 and args.rate_window_ms > 0:
        rate_limiter = TokenBucketLimiter(
            TokenBucketSettings(
                rate_limit=args.rate_limit,
                window_ms=args.rate_window_ms,
                burst_capacity=args.burst_capacity,
                dry_run=args.rate_limit_dry_run,
            )
        )

    while True:
        try:
            client_socket, client_address = server_socket.accept()
        except OSError as e:
            SERVER_LOGGER.error("Socket accept failed", extra={"error": str(e)})
            continue

        SERVER_LOGGER.debug("Accepted client", extra={"client": client_address})
        allowed, limit_type = connection_limiter.acquire(client_address[0])
        if not allowed:
            send_response(client_socket, connection_limited_response(limit_type))
            client_socket.close()
            continue
        client_socket.settimeout(60)
        threading.Thread(
            target=handle_client,
            args=(client_socket, args.directory, client_address, connection_limiter, rate_limiter),
            daemon=True,
        ).start()


if __name__ == "__main__":
    main()

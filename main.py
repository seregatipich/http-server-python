"""HTTP server supporting echo, user-agent, and file operations."""

import argparse
import gzip
import logging
import os
import socket
import ssl
import sys
import threading
from dataclasses import dataclass
from typing import Iterable, Iterator, Optional, Tuple

from logging_config import configure_logging

SERVER_LOGGER = logging.getLogger("http_server.server")
COMPRESSION_LOGGER = logging.getLogger("http_server.compression")

HEADER_DELIMITER = b"\r\n\r\n"

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
}


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
    client_socket: socket.socket, directory: str, client_address: tuple[str, int]
) -> None:
    """Process requests on a client socket until the connection is closed."""
    buffer = b""
    SERVER_LOGGER.debug("Connection opened", extra={"client": client_address})
    try:
        while True:
            request, buffer = receive_request(client_socket, buffer)
            if request is None:
                SERVER_LOGGER.debug(
                    "Client disconnected", extra={"client": client_address}
                )
                return
            response = build_response(request, directory)
            send_response(client_socket, response)
            if response.close_connection:
                break
    except (
        ConnectionError,
        TimeoutError,
        OSError,
        UnicodeDecodeError,
        ValueError,
    ):
        SERVER_LOGGER.exception(
            "Error handling client", extra={"client": client_address}
        )
    finally:
        client_socket.close()
        SERVER_LOGGER.debug("Connection closed", extra={"client": client_address})


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
    request_line = header_lines[0]
    method, path, _ = request_line.split(" ")
    headers = parse_headers(header_lines[1:])
    content_length = int(headers.get("content-length", 0))
    while len(remainder) < content_length:
        chunk = client_socket.recv(4096)
        if not chunk:
            return None, b""
        remainder += chunk
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


def build_response(request: HttpRequest, directory: str) -> HttpResponse:
    """Route the request to the appropriate handler and return a response."""
    if request.path == "/":
        return empty_response(request)
    if request.path.startswith("/echo/"):
        return text_response(request.path[6:], request)
    if request.path == "/user-agent":
        agent = request.headers.get("user-agent", "")
        return text_response(agent, request)
    if request.path.startswith("/files/"):
        return file_response(request, directory)
    return not_found_response(request)


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
    filename = request.path[7:]
    filepath = os.path.join(directory, filename)
    if request.method == "GET":
        if os.path.exists(filepath):
            headers = {
                "Content-Type": "application/octet-stream",
                **SECURITY_HEADERS,
            }
            SERVER_LOGGER.info(
                "Served file", extra={"path": filepath, "method": request.method}
            )
            return HttpResponse(
                "HTTP/1.1 200 OK",
                headers,
                b"",
                should_close(request.headers),
                body_iter=stream_file(filepath),
                use_chunked=True,
            )
        return not_found_response(request)
    if request.method == "POST":
        with open(filepath, "wb") as file_handle:
            file_handle.write(request.body)
        SERVER_LOGGER.info(
            "Stored file", extra={"path": filepath, "method": request.method}
        )
        return HttpResponse(
            "HTTP/1.1 201 Created",
            SECURITY_HEADERS.copy(),
            b"",
            should_close(request.headers),
        )
    SERVER_LOGGER.warning(
        "Unsupported method", extra={"path": filepath, "method": request.method}
    )
    return not_found_response(request)


def stream_file(filepath: str, chunk_size: int = 65536) -> Iterator[bytes]:
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

    while True:
        try:
            client_socket, client_address = server_socket.accept()
        except OSError as e:
            SERVER_LOGGER.error("Socket accept failed", extra={"error": str(e)})
            continue

        SERVER_LOGGER.debug("Accepted client", extra={"client": client_address})
        threading.Thread(
            target=handle_client,
            args=(client_socket, args.directory, client_address),
            daemon=True,
        ).start()


if __name__ == "__main__":
    main()

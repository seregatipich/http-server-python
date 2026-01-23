"""HTTP server supporting echo, user-agent, and file operations."""

import gzip
import os
import socket
import sys
import threading
from dataclasses import dataclass
from typing import Iterable, Optional

HEADER_DELIMITER = b"\r\n\r\n"


@dataclass
class HttpRequest:
    """Represents a parsed HTTP request."""

    method: str
    path: str
    headers: dict
    body: bytes


@dataclass
class HttpResponse:
    """Represents an HTTP response to be sent to a client."""

    status_line: str
    headers: dict
    body: bytes
    close_connection: bool
    body_iter: Optional[Iterable[bytes]] = None
    use_chunked: bool = False


def handle_client(client_socket, directory):
    """Process requests on a client socket until the connection is closed."""
    buffer = b""
    try:
        while True:
            request, buffer = receive_request(client_socket, buffer)
            if request is None:
                return
            response = build_response(request, directory)
            send_response(client_socket, response)
            if response.close_connection:
                break
    except (ConnectionError, TimeoutError, OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"Error handling client: {exc}")
    finally:
        client_socket.close()


def receive_request(client_socket, buffer):
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
    return HttpRequest(method, path, headers, body), leftover


def parse_headers(lines):
    """Convert raw header lines into a lowercase-keyed dictionary."""
    parsed = {}
    for line in lines:
        if ": " in line:
            name, value = line.split(": ", 1)
            parsed[name.lower()] = value
    return parsed


def build_response(request, directory):
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


def empty_response(request):
    """Return a 200 OK response with no body."""
    return HttpResponse("HTTP/1.1 200 OK", {}, b"", should_close(request.headers))


def text_response(message, request):
    """Return a text/plain response, compressing when appropriate."""
    payload = message.encode()
    payload, headers = compress_if_gzip_supported(payload, request.headers)
    base_headers = {"Content-Type": "text/plain", **headers}
    return HttpResponse("HTTP/1.1 200 OK", base_headers, payload, should_close(request.headers))


def file_response(request, directory):
    """Serve or write a file based on the HTTP method."""
    filename = request.path[7:]
    filepath = os.path.join(directory, filename)
    if request.method == "GET":
        if os.path.exists(filepath):
            headers = {"Content-Type": "application/octet-stream"}
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
        return HttpResponse("HTTP/1.1 201 Created", {}, b"", should_close(request.headers))
    return not_found_response(request)


def stream_file(filepath, chunk_size=65536):
    """Yield file contents in fixed-size chunks for streaming responses."""
    with open(filepath, "rb") as file_handle:
        while True:
            chunk = file_handle.read(chunk_size)
            if not chunk:
                break
            yield chunk


def not_found_response(request):
    """Return a 404 response reusing the connection preference."""
    return HttpResponse("HTTP/1.1 404 Not Found", {}, b"", should_close(request.headers))


def compress_if_gzip_supported(payload, headers):
    """Compress the payload when the request advertises gzip support."""
    if not accepts_gzip(headers):
        return payload, {}
    return gzip.compress(payload), {"Content-Encoding": "gzip"}


def accepts_gzip(headers):
    """Return True when the Accept-Encoding header includes gzip."""
    encodings = headers.get("accept-encoding", "")
    return any(value.strip() == "gzip" for value in encodings.split(","))


def should_close(headers):
    """Determine whether the connection should be closed after responding."""
    return headers.get("connection", "").lower() == "close"


def send_response(client_socket, response):
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


def main():
    """Start the HTTP server and spawn worker threads per connection."""
    directory = "."
    if "--directory" in sys.argv:
        directory = sys.argv[sys.argv.index("--directory") + 1]
    server_socket = socket.create_server(("localhost", 4221), reuse_port=True)
    while True:
        client_socket, _ = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, directory), daemon=True).start()


if __name__ == "__main__":
    main()

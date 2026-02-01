"""Unit tests validating HTTP response construction logic."""

import gzip
from pathlib import Path

from http_types import HttpRequest
from main import build_response


def make_request(
    path: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> HttpRequest:
    """Create a request targeted at the main server entry point."""

    return HttpRequest(method, path, headers or {}, body)


def test_build_response_root_returns_empty_response_when_missing_document(
    tmp_path: Path,
) -> None:
    """Root path returns empty 200 when no index document exists."""

    response = build_response(make_request("/"), str(tmp_path))
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.body == b""


def test_build_response_root_streams_index_file(tmp_path: Path) -> None:
    """Root path streams index.html when present."""

    index_file = tmp_path / "index.html"
    index_file.write_text("<h1>Hello</h1>")
    response = build_response(make_request("/"), str(tmp_path))
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.body == b""
    assert response.use_chunked
    assert response.body_iter is not None


def test_build_response_echo_respects_gzip(tmp_path: Path) -> None:
    """Echo endpoint should gzip payloads when requested."""

    headers = {"accept-encoding": "gzip"}
    response = build_response(
        make_request("/echo/sample", headers=headers), str(tmp_path)
    )
    assert response.headers.get("Content-Encoding") == "gzip"
    assert gzip.decompress(response.body) == b"sample"


def test_file_get_streams_existing_file(tmp_path: Path) -> None:
    """Files endpoint should stream bytes via chunked encoding."""

    file_path = tmp_path / "data.txt"
    file_path.write_bytes(b"payload")
    response = build_response(make_request(f"/files/{file_path.name}"), str(tmp_path))
    assert response.use_chunked
    assert response.body_iter is not None


def test_file_post_persists_payload(tmp_path: Path) -> None:
    """Posting to /files should persist the payload to disk."""

    body = b"uploaded"
    response = build_response(
        make_request("/files/uploaded.txt", method="POST", body=body),
        str(tmp_path),
    )
    assert response.status_line == "HTTP/1.1 201 Created"
    stored = (tmp_path / "uploaded.txt").read_bytes()
    assert stored == body

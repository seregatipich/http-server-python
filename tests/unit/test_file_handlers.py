"""Unit tests for static file and sandbox index route handlers."""

import mimetypes

import pytest

from pyhttpd.application.handlers.files import make_files_handler, make_index_handler
from pyhttpd.domain import (
    Forbidden,
    HttpResponse,
    MethodNotAllowed,
    NotFound,
)
from tests.unit._helpers import RecordingLogger, make_request


def _event_names(logger):
    return [event for _, event, _ in logger.events]


@pytest.mark.parametrize("path", ["/files/", "/files/../x", "/files/a/../b"])
def test_invalid_routes_raise_forbidden_and_log(ctx, tmp_path, path):
    """Invalid file routes raise Forbidden and emit a route_invalid event."""
    logger = RecordingLogger()
    handler = make_files_handler(str(tmp_path), logger, cors_config=None)
    with pytest.raises(Forbidden):
        handler(make_request(path=path), ctx)
    assert "route_invalid" in _event_names(logger)


def test_get_missing_file_raises_not_found(ctx, tmp_path):
    """GET on a path with no backing file raises NotFound."""
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)
    with pytest.raises(NotFound):
        handler(make_request(path="/files/absent.txt"), ctx)


def test_get_existing_file_streams_with_chunking(ctx, tmp_path):
    """GET on an existing file streams its bytes via a chunked body iterator."""
    payload = b"the quick brown fox" * 8
    (tmp_path / "data.txt").write_bytes(payload)
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)

    response = handler(make_request(path="/files/data.txt"), ctx)

    assert isinstance(response, HttpResponse)
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.use_chunked is True
    assert response.body_iter is not None
    assert b"".join(response.body_iter) == payload
    expected_type, _ = mimetypes.guess_type("data.txt")
    assert response.headers["Content-Type"] == expected_type


def test_post_persists_bytes_and_creates_parent_dirs(ctx, tmp_path):
    """POST writes the body to disk, creating intermediate directories."""
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)

    response = handler(
        make_request(method="POST", path="/files/sub/dir/out.txt", body=b"payload"), ctx
    )

    assert response.status_line == "HTTP/1.1 201 Created"
    assert (tmp_path / "sub" / "dir" / "out.txt").read_bytes() == b"payload"


def test_unsupported_method_on_directory_raises_forbidden(ctx, tmp_path):
    """An unsupported method targeting an existing directory raises Forbidden."""
    (tmp_path / "assets").mkdir()
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)
    with pytest.raises(Forbidden):
        handler(make_request(method="DELETE", path="/files/assets"), ctx)


def test_unsupported_method_on_file_raises_method_not_allowed(ctx, tmp_path):
    """An unsupported method on an existing file raises MethodNotAllowed."""
    (tmp_path / "data.txt").write_bytes(b"x")
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)
    with pytest.raises(MethodNotAllowed) as exc_info:
        handler(make_request(method="DELETE", path="/files/data.txt"), ctx)
    assert exc_info.value.allowed == ("GET", "POST")


def test_index_handler_returns_empty_when_document_missing(ctx, tmp_path):
    """Index handler returns an empty 200 when the index document is absent."""
    handler = make_index_handler(str(tmp_path), RecordingLogger(), cors_config=None)

    response = handler(make_request(path="/"), ctx)

    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.body == b""
    assert response.use_chunked is False
    assert response.body_iter is None


def test_index_handler_streams_when_document_present(ctx, tmp_path):
    """Index handler streams the index document when it exists."""
    payload = b"<html><body>home</body></html>"
    (tmp_path / "index.html").write_bytes(payload)
    handler = make_index_handler(str(tmp_path), RecordingLogger(), cors_config=None)

    response = handler(make_request(path="/"), ctx)

    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.use_chunked is True
    assert response.body_iter is not None
    assert b"".join(response.body_iter) == payload

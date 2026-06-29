"""Unit tests for static file and sandbox index route handlers."""

import mimetypes
import os

import pytest

from pyhttpd.application import make_files_handler, make_index_handler
from pyhttpd.domain import (
    FileServingOptions,
    Forbidden,
    HttpError,
    HttpResponse,
    MethodNotAllowed,
    NotFound,
)
from tests.unit._helpers import RecordingLogger, make_request


def _event_names(logger):
    return [event for _, event, _ in logger.events]


@pytest.mark.parametrize("path", ["/files/../x", "/files/a/../b"])
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


def test_get_existing_file_streams_with_content_length(ctx, tmp_path):
    """GET on an existing file streams its bytes with caching validators."""
    payload = b"the quick brown fox" * 8
    (tmp_path / "data.txt").write_bytes(payload)
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)

    response = handler(make_request(path="/files/data.txt"), ctx)

    assert isinstance(response, HttpResponse)
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.use_chunked is False
    assert response.content_length == len(payload)
    assert response.body_iter is not None
    assert b"".join(response.body_iter) == payload
    expected_type, _ = mimetypes.guess_type("data.txt")
    assert response.headers["Content-Type"] == expected_type
    assert response.headers["Accept-Ranges"] == "bytes"
    assert response.headers["ETag"]
    assert response.headers["Last-Modified"]


def test_concurrent_post_does_not_desync_in_flight_read(ctx, tmp_path):
    """A POST rewriting a file mid-stream must not corrupt an in-flight GET body."""
    original = b"X" * 200_000
    (tmp_path / "doc.bin").write_bytes(original)
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)

    response = handler(make_request(path="/files/doc.bin"), ctx)
    stream = response.body_iter
    first_chunk = next(stream)
    handler(make_request(method="POST", path="/files/doc.bin", body=b"Y" * 5), ctx)
    body = first_chunk + b"".join(stream)

    assert len(body) == response.content_length
    assert body == original


def test_get_content_length_matches_body_when_file_replaced_mid_response(ctx, tmp_path):
    """An atomic replace between header and stream must keep Content-Length == body."""
    original = b"A" * 1000
    target = tmp_path / "data.bin"
    target.write_bytes(original)
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)

    response = handler(make_request(path="/files/data.bin"), ctx)

    replacement = tmp_path / ".incoming"
    replacement.write_bytes(b"B" * 10)
    os.replace(replacement, target)

    body = b"".join(response.body_iter)
    assert len(body) == response.content_length
    assert body == original


def test_post_write_leaves_no_temp_file(ctx, tmp_path):
    """The atomic write path persists the body and cleans up its temporary file."""
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)

    handler(make_request(method="POST", path="/files/out.bin", body=b"payload"), ctx)

    assert (tmp_path / "out.bin").read_bytes() == b"payload"
    assert [p.name for p in tmp_path.iterdir()] == ["out.bin"]


def test_get_response_advertises_vary_accept_encoding(ctx, tmp_path):
    """Identity responses must advertise Vary so caches key on Accept-Encoding."""
    (tmp_path / "d.txt").write_bytes(b"x" * 50)
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)
    response = handler(make_request(path="/files/d.txt"), ctx)
    assert response.headers["Vary"] == "Accept-Encoding"


def test_gzip_variant_uses_a_distinct_etag(ctx, tmp_path):
    """The gzip representation must not share the identity ETag (cache safety)."""
    (tmp_path / "d.txt").write_text("hello world " * 50)
    options = FileServingOptions(gzip=True, gzip_min_bytes=1)
    handler = make_files_handler(
        str(tmp_path), RecordingLogger(), cors_config=None, options=options
    )
    identity = handler(make_request(path="/files/d.txt"), ctx)
    gzipped = handler(
        make_request(path="/files/d.txt", headers={"accept-encoding": "gzip"}), ctx
    )
    assert gzipped.headers["Content-Encoding"] == "gzip"
    assert gzipped.headers["ETag"] != identity.headers["ETag"]


def test_gzip_response_is_streamed_not_buffered(ctx, tmp_path):
    """gzip responses stream (chunked) instead of buffering the whole file."""
    import gzip as gzip_module

    payload = ("hello world " * 100).encode()
    (tmp_path / "d.txt").write_bytes(payload)
    options = FileServingOptions(gzip=True, gzip_min_bytes=1)
    handler = make_files_handler(
        str(tmp_path), RecordingLogger(), cors_config=None, options=options
    )
    response = handler(
        make_request(path="/files/d.txt", headers={"accept-encoding": "gzip"}), ctx
    )
    assert response.headers["Content-Encoding"] == "gzip"
    assert response.use_chunked is True
    assert response.content_length is None
    assert response.body == b""
    assert response.body_iter is not None
    assert gzip_module.decompress(b"".join(response.body_iter)) == payload


def test_if_range_mismatch_serves_full_content(ctx, tmp_path):
    """A non-matching If-Range must serve the full 200, not a 206 with bad data."""
    (tmp_path / "d.bin").write_bytes(b"0123456789")
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)
    response = handler(
        make_request(
            path="/files/d.bin",
            headers={"range": "bytes=0-4", "if-range": '"stale-etag"'},
        ),
        ctx,
    )
    assert response.status_line == "HTTP/1.1 200 OK"


def test_if_range_match_serves_partial_content(ctx, tmp_path):
    """A matching If-Range validator still yields a 206."""
    (tmp_path / "d.bin").write_bytes(b"0123456789")
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)
    etag = handler(make_request(path="/files/d.bin"), ctx).headers["ETag"]
    response = handler(
        make_request(
            path="/files/d.bin", headers={"range": "bytes=0-4", "if-range": etag}
        ),
        ctx,
    )
    assert response.status_line == "HTTP/1.1 206 Partial Content"


def test_post_to_directory_returns_client_error(ctx, tmp_path):
    """POST onto a directory path yields a 4xx, never an unhandled 500."""
    (tmp_path / "sub").mkdir()
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)
    with pytest.raises(HttpError) as exc_info:
        handler(make_request(method="POST", path="/files/sub", body=b"x"), ctx)
    assert 400 <= exc_info.value.status < 500


def test_post_under_file_parent_returns_client_error(ctx, tmp_path):
    """POST under a path whose parent is a file yields a 4xx, not a 500."""
    (tmp_path / "afile").write_bytes(b"x")
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)
    with pytest.raises(HttpError) as exc_info:
        handler(make_request(method="POST", path="/files/afile/child", body=b"x"), ctx)
    assert 400 <= exc_info.value.status < 500


def test_overlong_path_returns_client_error(ctx, tmp_path):
    """An over-long path component yields a 4xx, not an unhandled OSError 500."""
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)
    with pytest.raises(HttpError) as exc_info:
        handler(make_request(path="/files/" + "a" * 5000), ctx)
    assert 400 <= exc_info.value.status < 500


def test_autoindex_lists_sandbox_root(ctx, tmp_path):
    """With autoindex enabled, /files/ lists the sandbox root instead of 403."""
    (tmp_path / "a.txt").write_bytes(b"x")
    options = FileServingOptions(autoindex=True)
    handler = make_files_handler(
        str(tmp_path), RecordingLogger(), cors_config=None, options=options
    )
    response = handler(make_request(path="/files/"), ctx)
    assert response.status_line == "HTTP/1.1 200 OK"


def test_root_without_autoindex_is_not_found(ctx, tmp_path):
    """Without autoindex, /files/ is a 404 (a directory has no document)."""
    handler = make_files_handler(str(tmp_path), RecordingLogger(), cors_config=None)
    with pytest.raises(NotFound):
        handler(make_request(path="/files/"), ctx)


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
        handler(make_request(method="PATCH", path="/files/data.txt"), ctx)
    assert exc_info.value.allowed == ("DELETE", "GET", "HEAD", "POST", "PUT")


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

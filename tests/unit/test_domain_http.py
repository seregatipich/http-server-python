"""Unit tests for pyhttpd.domain.http value types and should_close."""

from pyhttpd.domain import HttpRequest, HttpResponse, should_close


def test_http_request_holds_provided_fields() -> None:
    """HttpRequest exposes the method, path, headers, and body it was built with."""
    request = HttpRequest(
        method="POST",
        path="/upload",
        headers={"content-type": "application/json"},
        body=b'{"name": "value"}',
    )
    assert request.method == "POST"
    assert request.path == "/upload"
    assert request.headers == {"content-type": "application/json"}
    assert request.body == b'{"name": "value"}'


def test_http_request_equality_by_value() -> None:
    """Two HttpRequest instances with identical fields compare equal."""
    first = HttpRequest(method="GET", path="/", headers={}, body=b"")
    second = HttpRequest(method="GET", path="/", headers={}, body=b"")
    assert first == second


def test_http_request_inequality_on_differing_path() -> None:
    """HttpRequest instances differing only by path are not equal."""
    base = HttpRequest(method="GET", path="/", headers={}, body=b"")
    other = HttpRequest(method="GET", path="/other", headers={}, body=b"")
    assert base != other


def test_http_response_defaults_streaming_fields() -> None:
    """HttpResponse defaults body_iter to None and use_chunked to False."""
    response = HttpResponse(
        status_line="HTTP/1.1 200 OK",
        headers={"content-length": "2"},
        body=b"ok",
        close_connection=False,
    )
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.headers == {"content-length": "2"}
    assert response.body == b"ok"
    assert response.close_connection is False
    assert response.body_iter is None
    assert response.use_chunked is False


def test_http_response_accepts_explicit_streaming_fields() -> None:
    """HttpResponse stores an explicit body_iter and chunked flag."""
    chunks = [b"a", b"b"]
    response = HttpResponse(
        status_line="HTTP/1.1 200 OK",
        headers={},
        body=b"",
        close_connection=True,
        body_iter=iter(chunks),
        use_chunked=True,
    )
    assert response.close_connection is True
    assert response.use_chunked is True
    assert list(response.body_iter) == chunks


def test_should_close_true_for_close_header() -> None:
    """should_close returns True when Connection requests close."""
    assert should_close({"connection": "close"}) is True


def test_should_close_case_insensitive_value() -> None:
    """should_close treats the Connection close value case-insensitively."""
    assert should_close({"connection": "Close"}) is True
    assert should_close({"connection": "CLOSE"}) is True


def test_should_close_false_for_keep_alive() -> None:
    """should_close returns False when Connection requests keep-alive."""
    assert should_close({"connection": "keep-alive"}) is False


def test_should_close_false_when_header_absent() -> None:
    """should_close defaults to False on HTTP/1.1 with no Connection header."""
    assert should_close({}) is False


def test_should_close_false_for_empty_connection_value() -> None:
    """should_close returns False when the Connection value is empty."""
    assert should_close({"connection": ""}) is False


def test_should_close_false_for_unrelated_token() -> None:
    """should_close ignores Connection values that are not exactly close."""
    assert should_close({"connection": "upgrade"}) is False

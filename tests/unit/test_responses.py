"""Unit tests validating HTTP response construction logic."""

import gzip
from pathlib import Path
from unittest.mock import Mock

from pyhttpd.application.context import RequestContext
from pyhttpd.application.rendering import (
    ErrorMapper,
    connection_limited_response,
    internal_error_response,
    method_not_allowed_response,
    rate_limited_response,
)
from pyhttpd.application.routing import make_default_router
from pyhttpd.domain import SECURITY_HEADERS, HttpError, HttpRequest, RateLimitDecision
from pyhttpd.domain.errors import (
    BadRequest,
    Forbidden,
    MethodNotAllowed,
    NotFound,
    ServiceUnavailable,
)
from tests.unit._helpers import make_request


def route_request(request: HttpRequest, directory: str):
    """Dispatch through the default router, mapping domain errors to responses."""

    router = make_default_router(directory, None, Mock())
    ctx = RequestContext(correlation_id=None, start_ns=0)
    try:
        return router.dispatch(request, ctx)
    except HttpError as error:
        return ErrorMapper.to_response(error, request, None)


def test_build_response_root_returns_empty_response_when_missing_document(
    tmp_path: Path,
) -> None:
    """Root path returns empty 200 when no index document exists."""

    response = route_request(make_request("/"), str(tmp_path))
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.body == b""


def test_build_response_root_streams_index_file(tmp_path: Path) -> None:
    """Root path streams index.html when present."""

    index_file = tmp_path / "index.html"
    index_file.write_text("<h1>Hello</h1>")
    response = route_request(make_request("/"), str(tmp_path))
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.body == b""
    assert response.use_chunked
    assert response.body_iter is not None


def test_build_response_echo_respects_gzip(tmp_path: Path) -> None:
    """Echo endpoint should gzip payloads when requested."""

    headers = {"accept-encoding": "gzip"}
    response = route_request(
        make_request("/echo/sample", headers=headers), str(tmp_path)
    )
    assert response.headers.get("Content-Encoding") == "gzip"
    assert gzip.decompress(response.body) == b"sample"


def test_file_get_streams_existing_file(tmp_path: Path) -> None:
    """Files endpoint should stream bytes via chunked encoding."""

    file_path = tmp_path / "data.txt"
    file_path.write_bytes(b"payload")
    response = route_request(make_request(f"/files/{file_path.name}"), str(tmp_path))
    assert response.use_chunked
    assert response.body_iter is not None


def test_file_post_persists_payload(tmp_path: Path) -> None:
    """Posting to /files should persist the payload to disk."""

    body = b"uploaded"
    response = route_request(
        make_request("/files/uploaded.txt", method="POST", body=body),
        str(tmp_path),
    )
    assert response.status_line == "HTTP/1.1 201 Created"
    stored = (tmp_path / "uploaded.txt").read_bytes()
    assert stored == body


def test_file_regular_options_returns_method_not_allowed(tmp_path: Path) -> None:
    """Non-preflight OPTIONS requests to /files should fail cleanly."""

    response = route_request(
        make_request("/files/item.txt", method="OPTIONS"),
        str(tmp_path),
    )
    assert response.status_line == "HTTP/1.1 405 Method Not Allowed"
    assert response.headers["Allow"] == "GET, POST"


def make_decision(reset_seconds: float) -> RateLimitDecision:
    """Build a RateLimitDecision carrying only the fields under test."""

    return RateLimitDecision(
        allowed=False,
        limit=10,
        remaining=0,
        reset_seconds=reset_seconds,
        headers={},
        dry_run=False,
        window_seconds=1.0,
    )


def test_rate_limited_response_floors_retry_after_to_one() -> None:
    """A zero reset window still advertises a one-second Retry-After."""

    response = rate_limited_response(make_decision(0), None, SECURITY_HEADERS)
    assert response.status_line == "HTTP/1.1 429 Too Many Requests"
    assert response.headers["Retry-After"] == "1"
    assert response.body == b"Rate limit exceeded"


def test_rate_limited_response_truncates_fractional_reset() -> None:
    """A fractional reset window is truncated toward the integer seconds."""

    response = rate_limited_response(make_decision(2.7), None, SECURITY_HEADERS)
    assert response.status_line == "HTTP/1.1 429 Too Many Requests"
    assert response.headers["Retry-After"] == "2"


def test_connection_limited_response_names_the_limit_type() -> None:
    """A named limit type is woven into the response body."""

    response = connection_limited_response("global", SECURITY_HEADERS)
    assert response.status_line == "HTTP/1.1 503 Service Unavailable"
    assert response.body == b"global connection limit exceeded"
    assert response.headers["Retry-After"] == "1"


def test_connection_limited_response_without_limit_type() -> None:
    """An absent limit type yields the generic 503 body."""

    response = connection_limited_response(None, SECURITY_HEADERS)
    assert response.status_line == "HTTP/1.1 503 Service Unavailable"
    assert response.body == b"Connection limit exceeded"
    assert response.headers["Retry-After"] == "1"


def test_method_not_allowed_response_sorts_allow_header() -> None:
    """The Allow header lists supported methods in sorted order."""

    response = method_not_allowed_response(
        make_request("/files/item.txt", method="PUT"),
        None,
        SECURITY_HEADERS,
        ["POST", "GET"],
    )
    assert response.status_line == "HTTP/1.1 405 Method Not Allowed"
    assert response.headers["Allow"] == "GET, POST"


def test_internal_error_response_closes_without_request() -> None:
    """A missing request defaults the connection to close."""

    response = internal_error_response(None, SECURITY_HEADERS)
    assert response.status_line == "HTTP/1.1 500 Internal Server Error"
    assert response.close_connection is True


def test_internal_error_response_keeps_alive_when_requested() -> None:
    """A keep-alive request preserves the connection on a 500."""

    response = internal_error_response(
        make_request("/", headers={"connection": "keep-alive"}),
        SECURITY_HEADERS,
    )
    assert response.close_connection is False


def test_internal_error_response_closes_on_connection_close() -> None:
    """An explicit Connection: close header closes the connection."""

    response = internal_error_response(
        make_request("/", headers={"connection": "close"}),
        SECURITY_HEADERS,
    )
    assert response.close_connection is True


def test_error_mapper_routes_service_unavailable_to_draining() -> None:
    """ServiceUnavailable dispatches to the draining 503 builder."""

    response = ErrorMapper.to_response(ServiceUnavailable(), None, None)
    assert response.status_line == "HTTP/1.1 503 Service Unavailable"


def test_error_mapper_falls_through_to_internal_error() -> None:
    """An unmatched HttpError falls through to the 500 builder."""

    response = ErrorMapper.to_response(HttpError(), None, None)
    assert response.status_line == "HTTP/1.1 500 Internal Server Error"


def test_error_mapper_routes_not_found() -> None:
    """NotFound dispatches to the 404 builder."""

    response = ErrorMapper.to_response(NotFound(), make_request("/missing"), None)
    assert response.status_line == "HTTP/1.1 404 Not Found"


def test_error_mapper_routes_bad_request() -> None:
    """BadRequest dispatches to the 400 builder."""

    response = ErrorMapper.to_response(BadRequest(), make_request("/bad"), None)
    assert response.status_line == "HTTP/1.1 400 Bad Request"


def test_error_mapper_routes_forbidden() -> None:
    """Forbidden dispatches to the 403 builder."""

    response = ErrorMapper.to_response(Forbidden(), make_request("/secret"), None)
    assert response.status_line == "HTTP/1.1 403 Forbidden"


def test_error_mapper_routes_method_not_allowed_with_allow_header() -> None:
    """MethodNotAllowed dispatches to the 405 builder with a sorted Allow header."""

    response = ErrorMapper.to_response(
        MethodNotAllowed(["POST", "GET"]),
        make_request("/files/item.txt", method="PUT"),
        None,
    )
    assert response.status_line == "HTTP/1.1 405 Method Not Allowed"
    assert response.headers["Allow"] == "GET, POST"

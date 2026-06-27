"""Unit tests for structured JSON error bodies (F2)."""

import json

from pyhttpd.application.rendering import ErrorMapper, apply_error_format
from pyhttpd.domain import HttpResponse, NotFound
from tests.unit._helpers import make_request


def _error_response(status_line: str, body: bytes = b"") -> HttpResponse:
    headers = {"Content-Security-Policy": "default-src 'self'"}
    return HttpResponse(status_line, headers, body, True)


def test_text_format_is_passthrough() -> None:
    response = _error_response("HTTP/1.1 404 Not Found")
    assert apply_error_format(response, "text") is response


def test_json_format_sets_body_and_content_type() -> None:
    response = _error_response("HTTP/1.1 404 Not Found")
    result = apply_error_format(response, "json", request_id="cid-1")

    assert result.headers["Content-Type"] == "application/json"
    assert json.loads(result.body) == {
        "error": "Not Found",
        "status": 404,
        "request_id": "cid-1",
    }


def test_json_format_request_id_null_when_absent() -> None:
    response = _error_response("HTTP/1.1 400 Bad Request")
    result = apply_error_format(response, "json")

    payload = json.loads(result.body)
    assert payload == {"error": "Bad Request", "status": 400, "request_id": None}


def test_json_format_preserves_existing_headers() -> None:
    response = _error_response("HTTP/1.1 429 Too Many Requests", b"Rate limit exceeded")
    response.headers["Retry-After"] = "1"

    result = apply_error_format(response, "json", request_id="cid-2")

    assert result.headers["Retry-After"] == "1"
    assert result.headers["Content-Type"] == "application/json"
    assert json.loads(result.body)["status"] == 429


def test_json_format_keeps_close_connection() -> None:
    response = _error_response("HTTP/1.1 404 Not Found")
    result = apply_error_format(response, "json", request_id="cid")
    assert result.close_connection is True


def test_json_format_skips_streaming_responses() -> None:
    response = HttpResponse(
        "HTTP/1.1 500 Internal Server Error",
        {},
        b"",
        True,
        body_iter=iter([b"chunk"]),
        use_chunked=True,
    )
    assert apply_error_format(response, "json", request_id="cid") is response


def test_error_mapper_json_not_found() -> None:
    request = make_request(path="/missing")
    response = ErrorMapper.to_response(
        NotFound("no route"), request, None, error_format="json", request_id="cid-3"
    )

    assert response.status_line == "HTTP/1.1 404 Not Found"
    assert response.headers["Content-Type"] == "application/json"
    assert json.loads(response.body) == {
        "error": "Not Found",
        "status": 404,
        "request_id": "cid-3",
    }


def test_error_mapper_text_default_unchanged() -> None:
    request = make_request(path="/missing")
    response = ErrorMapper.to_response(NotFound("no route"), request, None)

    assert response.body == b""
    assert "Content-Type" not in response.headers


def test_error_mapper_internal_error_json() -> None:
    request = make_request()
    response = ErrorMapper.internal_error(
        request, None, error_format="json", request_id="cid-4"
    )

    assert response.status_line == "HTTP/1.1 500 Internal Server Error"
    assert json.loads(response.body) == {
        "error": "Internal Server Error",
        "status": 500,
        "request_id": "cid-4",
    }

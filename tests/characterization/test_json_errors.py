"""Golden pins for the opt-in JSON error body format (F2)."""

from __future__ import annotations

import json

import pytest

from pyhttpd.domain import SECURITY_HEADERS
from tests.characterization.raw_client import parse_response, send_raw

pytestmark = pytest.mark.integration


def _assert_security_headers(headers: dict[str, str]) -> None:
    for name, expected in SECURITY_HEADERS.items():
        assert headers[name] == expected


def test_not_found_404_json_body(json_error_server_process) -> None:
    """An in-chain 404 carries a JSON body whose request_id mirrors X-Request-ID."""

    raw = send_raw(
        json_error_server_process["host"],
        json_error_server_process["port"],
        b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 404 Not Found"
    assert headers["Content-Type"] == "application/json"
    assert headers["Content-Length"] == str(len(body))
    _assert_security_headers(headers)
    payload = json.loads(body)
    assert payload["status"] == 404
    assert payload["error"] == "Not Found"
    assert payload["request_id"] == headers["X-Request-ID"]


def test_bad_request_400_json_body_prechain(json_error_server_process) -> None:
    """A malformed request line (pre-chain path) is also JSON-formatted."""

    raw = send_raw(
        json_error_server_process["host"],
        json_error_server_process["port"],
        b"GET\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 400 Bad Request"
    assert headers["Content-Type"] == "application/json"
    assert headers["Content-Length"] == str(len(body))
    payload = json.loads(body)
    assert payload["status"] == 400
    assert payload["error"] == "Bad Request"
    assert payload["request_id"] == headers["X-Request-ID"]


def test_method_not_allowed_405_json_preserves_allow(json_error_server_process) -> None:
    """A JSON 405 keeps the Allow header alongside the JSON body."""

    raw = send_raw(
        json_error_server_process["host"],
        json_error_server_process["port"],
        b"DELETE /echo/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    status_line, headers, body = parse_response(raw)

    assert status_line == "HTTP/1.1 405 Method Not Allowed"
    assert headers["Allow"] == "GET, HEAD"
    assert headers["Content-Type"] == "application/json"
    assert json.loads(body)["status"] == 405

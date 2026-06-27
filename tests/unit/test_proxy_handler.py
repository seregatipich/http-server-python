"""Unit tests for the reverse-proxy dispatch wrapper (F8)."""

from argparse import Namespace

import pytest

from pyhttpd.application.handlers.proxy import make_proxy_dispatch
from pyhttpd.composition import _create_proxy_targets
from pyhttpd.domain import BadGateway, HttpResponse
from pyhttpd.domain.proxy import UpstreamResponse, parse_proxy_pass
from tests.unit._helpers import RecordingLogger, make_context, make_request

TARGETS = (parse_proxy_pass("/api/=http://backend:80"),)


def _fallback(_request, _ctx) -> HttpResponse:
    return HttpResponse("HTTP/1.1 200 OK", {}, b"fallback", False)


def _dispatch(forwarder):
    return make_proxy_dispatch(
        TARGETS, forwarder, "1.2.3.4", 5.0, RecordingLogger(), _fallback
    )


def test_non_matching_path_uses_fallback() -> None:
    def forwarder(*_args):
        raise AssertionError("non-matching paths must not be forwarded")

    response = _dispatch(forwarder)(make_request(path="/other"), make_context())
    assert response.body == b"fallback"


def test_matching_path_is_proxied_with_known_length() -> None:
    captured: dict[str, object] = {}

    def forwarder(_target, _method, path, headers, _body, _timeout):
        captured["path"] = path
        captured["headers"] = headers
        return UpstreamResponse(
            200,
            "OK",
            {"Content-Type": "application/json", "Content-Length": "2"},
            iter([b"{}"]),
        )

    response = _dispatch(forwarder)(
        make_request(path="/api/users", query="q=1"), make_context()
    )
    assert response.status_line == "HTTP/1.1 200 OK"
    assert captured["path"] == "/users?q=1"
    assert response.content_length == 2
    assert response.use_chunked is False
    assert response.streaming is True
    assert "Content-Length" not in response.headers
    assert b"".join(response.body_iter) == b"{}"


def test_proxied_response_chunked_without_content_length() -> None:
    def forwarder(*_args):
        return UpstreamResponse(
            200, "OK", {"Content-Type": "text/plain"}, iter([b"data"])
        )

    response = _dispatch(forwarder)(make_request(path="/api/x"), make_context())
    assert response.use_chunked is True
    assert response.content_length is None


def test_upstream_error_propagates_for_central_mapping() -> None:
    def forwarder(*_args):
        raise BadGateway("upstream down")

    with pytest.raises(BadGateway):
        _dispatch(forwarder)(make_request(path="/api/x"), make_context())


def test_create_proxy_targets_enforces_allowlist() -> None:
    args = Namespace(
        proxy_pass=["/up/=http://evil:80"],
        proxy_allow_host=["trusted"],
        proxy_timeout=5.0,
    )
    with pytest.raises(SystemExit):
        _create_proxy_targets(args)


def test_create_proxy_targets_accepts_allowlisted_host() -> None:
    args = Namespace(
        proxy_pass=["/up/=http://trusted:80"],
        proxy_allow_host=["trusted"],
        proxy_timeout=5.0,
    )
    targets = _create_proxy_targets(args)
    assert len(targets) == 1
    assert targets[0].host == "trusted"

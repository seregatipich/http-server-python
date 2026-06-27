"""Unit tests for pure reverse-proxy helpers (F8)."""

import pytest

from pyhttpd.domain.proxy import (
    filter_request_headers,
    filter_response_headers,
    parse_proxy_pass,
    upstream_path,
)


def test_parse_proxy_pass_http_with_base_path() -> None:
    target = parse_proxy_pass("/api/=http://backend:9000/v1")
    assert target.mount == "/api/"
    assert target.scheme == "http"
    assert target.host == "backend"
    assert target.port == 9000
    assert target.base_path == "/v1"
    assert target.authority == "backend:9000"


def test_parse_proxy_pass_defaults_https_port() -> None:
    target = parse_proxy_pass("/x=https://example.com")
    assert target.port == 443
    assert target.authority == "example.com"


@pytest.mark.parametrize("spec", ["noequals", "/x=ftp://bad", "nomount=http://x"])
def test_parse_proxy_pass_rejects_invalid(spec: str) -> None:
    with pytest.raises(ValueError):
        parse_proxy_pass(spec)


def test_upstream_path_maps_suffix_and_query() -> None:
    target = parse_proxy_pass("/api/=http://b:80/v1")
    assert upstream_path(target, "/api/users", "q=1") == "/v1/users?q=1"


def test_upstream_path_root_when_empty() -> None:
    target = parse_proxy_pass("/api=http://b:80")
    assert upstream_path(target, "/api", "") == "/"


def test_filter_request_headers_strips_hop_by_hop_and_forwards() -> None:
    target = parse_proxy_pass("/api/=http://backend:9000")
    headers = {
        "host": "client",
        "connection": "keep-alive",
        "x-custom": "v",
        "upgrade": "h2c",
    }
    out = filter_request_headers(headers, target, "1.2.3.4", "http")
    assert out["Host"] == "backend:9000"
    assert "connection" not in out
    assert "upgrade" not in out
    assert out["x-custom"] == "v"
    assert out["X-Forwarded-For"] == "1.2.3.4"
    assert out["X-Forwarded-Proto"] == "http"
    assert out["Via"] == "1.1 pyhttpd"


def test_filter_request_headers_appends_to_existing_forwarded_for() -> None:
    target = parse_proxy_pass("/api/=http://b:80")
    out = filter_request_headers(
        {"x-forwarded-for": "9.9.9.9"}, target, "1.2.3.4", "http"
    )
    assert out["X-Forwarded-For"] == "9.9.9.9, 1.2.3.4"


def test_filter_response_headers_strips_hop_by_hop() -> None:
    out = filter_response_headers(
        {
            "Content-Type": "text/plain",
            "Transfer-Encoding": "chunked",
            "Connection": "close",
        }
    )
    assert out == {"Content-Type": "text/plain"}

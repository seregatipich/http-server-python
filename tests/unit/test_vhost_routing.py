"""Unit tests for virtual-host routing (F9)."""

from pyhttpd.application.routing import make_vhost_router, normalize_host
from pyhttpd.domain import HttpResponse
from tests.unit._helpers import make_context, make_request


class StubRouter:
    """Router double that echoes which directory it was built for."""

    def __init__(self, directory: str) -> None:
        self.directory = directory

    def dispatch(self, _request, _ctx) -> HttpResponse:
        return HttpResponse("HTTP/1.1 200 OK", {}, self.directory.encode(), False)


def _build_router(directory: str) -> StubRouter:
    return StubRouter(directory)


def test_normalize_host_strips_port_and_lowercases() -> None:
    assert normalize_host("Example.COM:8080") == "example.com"
    assert normalize_host("  host  ") == "host"
    assert normalize_host("") == ""


def test_vhost_router_selects_directory_by_host() -> None:
    dispatch = make_vhost_router(
        {"a.test": "/srv/a", "b.test": "/srv/b"}, "/srv/default", _build_router
    )
    response = dispatch(make_request(headers={"host": "a.test"}), make_context())
    assert response.body == b"/srv/a"


def test_vhost_router_normalizes_request_host() -> None:
    dispatch = make_vhost_router({"a.test": "/srv/a"}, "/srv/default", _build_router)
    response = dispatch(make_request(headers={"host": "A.TEST:9999"}), make_context())
    assert response.body == b"/srv/a"


def test_vhost_router_falls_back_to_default() -> None:
    dispatch = make_vhost_router({"a.test": "/srv/a"}, "/srv/default", _build_router)
    response = dispatch(make_request(headers={"host": "unknown.test"}), make_context())
    assert response.body == b"/srv/default"


def test_vhost_router_missing_host_uses_default() -> None:
    dispatch = make_vhost_router({"a.test": "/srv/a"}, "/srv/default", _build_router)
    response = dispatch(make_request(), make_context())
    assert response.body == b"/srv/default"

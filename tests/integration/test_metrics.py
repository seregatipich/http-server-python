"""Integration tests for the Prometheus metrics endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Generator

import pytest
import requests

from tests.conftest import _launch_server  # type: ignore[attr-defined]
from tests.utils.http import reserve_port

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from _pytest.tmpdir import TempPathFactory

    from tests.conftest import ServerProcessInfo


@pytest.fixture(name="metrics_server_process")
def _metrics_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator["ServerProcessInfo", None, None]:
    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-metrics")
    log_file = directory / "server.log"
    yield from _launch_server(host, port, directory, ["--metrics"], log_file=log_file)


def test_metrics_endpoint_reports_requests(
    metrics_server_process: "ServerProcessInfo",
) -> None:
    """After traffic, /metrics exposes counters in Prometheus format."""
    base_url = metrics_server_process["base_url"]
    requests.get(f"{base_url}/", timeout=5)
    requests.get(f"{base_url}/echo/abc", timeout=5)
    requests.get(f"{base_url}/missing", timeout=5)

    response = requests.get(f"{base_url}/metrics", timeout=5)
    assert response.status_code == 200
    assert response.headers["Content-Type"] == (
        "text/plain; version=0.0.4; charset=utf-8"
    )
    body = response.text
    assert "# TYPE http_requests_total counter" in body
    assert 'http_requests_total{method="GET",route="/",status="200"}' in body
    assert 'route="/echo/"' in body
    assert "http_request_duration_seconds_bucket" in body


def test_metrics_endpoint_excludes_itself(
    metrics_server_process: "ServerProcessInfo",
) -> None:
    """The /metrics route is not counted in its own request metrics."""
    base_url = metrics_server_process["base_url"]
    requests.get(f"{base_url}/metrics", timeout=5)
    body = requests.get(f"{base_url}/metrics", timeout=5).text
    assert 'route="/metrics"' not in body


def test_metrics_endpoint_absent_when_disabled(base_url: str) -> None:
    """Without --metrics the endpoint is not routed (opt-in)."""
    response = requests.get(f"{base_url}/metrics", timeout=5)
    assert response.status_code == 404

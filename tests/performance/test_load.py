"""Load and throughput tests for the live pyhttpd server.

These scenarios are marked ``performance`` and are skipped by the default
suite (``addopts = -m 'not performance'``). Run them explicitly with::

    pytest -m performance

The whole module is tuned to finish well under ~15 seconds against a local
server while still exercising a few hundred sequential and concurrent
requests per endpoint.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
import requests

pytestmark = pytest.mark.performance

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo

SEQUENTIAL_REQUESTS = 300
CONCURRENT_REQUESTS = 400
CONCURRENT_WORKERS = 16
REQUEST_TIMEOUT = 10.0
MIN_THROUGHPUT_RPS = 50.0


@pytest.fixture(autouse=True)
def _disable_throttling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lift rate and connection limits before ``server_process`` spawns.

    The shared ``server_process`` fixture starts pyhttpd with its production
    defaults (50 requests per 10s window, burst 25, 200 connections), which a
    throughput probe firing hundreds of requests would immediately trip. This
    autouse fixture resolves before ``server_process`` and exports the
    documented overrides so the subprocess inherits an unthrottled config.
    """

    monkeypatch.setenv("HTTP_SERVER_RATE_LIMIT", "0")
    monkeypatch.setenv("HTTP_SERVER_MAX_CONNECTIONS", "0")
    monkeypatch.setenv("HTTP_SERVER_MAX_CONNECTIONS_PER_IP", "0")


@dataclass(slots=True)
class LoadResult:
    """Outcome of a batch of timed requests against one or more endpoints."""

    statuses: list[int]
    latencies_ms: list[float]
    wall_seconds: float

    @property
    def request_count(self) -> int:
        """Total number of requests that completed."""

        return len(self.statuses)

    @property
    def error_count(self) -> int:
        """Number of responses whose status code was not 200."""

        return sum(1 for status in self.statuses if status != 200)

    @property
    def error_rate(self) -> float:
        """Fraction of requests that did not return a 200 status."""

        if not self.statuses:
            return 0.0
        return self.error_count / len(self.statuses)

    @property
    def throughput_rps(self) -> float:
        """Completed requests per wall-clock second."""

        if self.wall_seconds <= 0:
            return 0.0
        return self.request_count / self.wall_seconds


def _percentile(samples: list[float], percentile: float) -> float:
    """Return the linear-interpolated percentile of ``samples``."""

    if not samples:
        return 0.0
    ordered = sorted(samples)
    rank = (percentile / 100.0) * (len(ordered) - 1)
    lower_index = int(rank)
    upper_index = min(lower_index + 1, len(ordered) - 1)
    weight = rank - lower_index
    return ordered[lower_index] * (1.0 - weight) + ordered[upper_index] * weight


def _issue_request(session: requests.Session, url: str) -> tuple[int, float]:
    """Issue one GET request, fully reading the body, and time it in ms."""

    start = time.perf_counter()
    response = session.get(url, timeout=REQUEST_TIMEOUT)
    _ = response.content
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    response.close()
    return response.status_code, elapsed_ms


def _run_sequential(url: str, count: int) -> LoadResult:
    """Drive ``count`` back-to-back requests against ``url`` on one session."""

    statuses: list[int] = []
    latencies_ms: list[float] = []
    with requests.Session() as session:
        _issue_request(session, url)
        start = time.perf_counter()
        for _ in range(count):
            status, elapsed_ms = _issue_request(session, url)
            statuses.append(status)
            latencies_ms.append(elapsed_ms)
        wall_seconds = time.perf_counter() - start
    return LoadResult(statuses, latencies_ms, wall_seconds)


def _run_concurrent(urls: list[str], workers: int) -> LoadResult:
    """Fan ``urls`` out across a thread pool, one session per worker thread."""

    statuses: list[int] = []
    latencies_ms: list[float] = []
    thread_local = threading.local()

    def issue(url: str) -> tuple[int, float]:
        session: requests.Session | None = getattr(thread_local, "session", None)
        if session is None:
            session = requests.Session()
            thread_local.session = session
        return _issue_request(session, url)

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(issue, url) for url in urls]
        for future in as_completed(futures):
            status, elapsed_ms = future.result()
            statuses.append(status)
            latencies_ms.append(elapsed_ms)
    wall_seconds = time.perf_counter() - start
    return LoadResult(statuses, latencies_ms, wall_seconds)


def _report(label: str, result: LoadResult) -> None:
    """Print throughput and latency percentiles for a finished batch."""

    p50 = _percentile(result.latencies_ms, 50.0)
    p95 = _percentile(result.latencies_ms, 95.0)
    print(
        f"\n[perf] {label}: "
        f"{result.request_count} requests, "
        f"{result.throughput_rps:.1f} req/s, "
        f"p50={p50:.2f}ms, p95={p95:.2f}ms, "
        f"errors={result.error_count} "
        f"(rate={result.error_rate:.3f})"
    )


def _assert_healthy(result: LoadResult) -> None:
    """Assert a finished batch met the conservative load expectations."""

    assert all(status == 200 for status in result.statuses)
    assert result.error_rate == 0.0
    assert result.throughput_rps > MIN_THROUGHPUT_RPS


@pytest.mark.parametrize("path", ["/", "/echo/load-test"])
def test_sequential_throughput(server_process: "ServerProcessInfo", path: str) -> None:
    """Sequential GETs sustain the throughput floor with zero errors."""

    result = _run_sequential(f"{server_process['base_url']}{path}", SEQUENTIAL_REQUESTS)
    _report(f"sequential GET {path}", result)
    _assert_healthy(result)


def test_concurrent_requests_all_succeed(
    server_process: "ServerProcessInfo",
) -> None:
    """A thread pool hammering both endpoints returns 200 for every request."""

    base_url = server_process["base_url"]
    endpoints = (f"{base_url}/", f"{base_url}/echo/concurrent")
    urls = [endpoints[index % len(endpoints)] for index in range(CONCURRENT_REQUESTS)]

    result = _run_concurrent(urls, CONCURRENT_WORKERS)
    _report(f"concurrent x{CONCURRENT_WORKERS} GET /, /echo", result)

    assert result.request_count == CONCURRENT_REQUESTS
    _assert_healthy(result)

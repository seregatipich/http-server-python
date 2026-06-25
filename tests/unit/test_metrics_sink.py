"""Unit tests for the thread-safe metrics sink adapter."""

import threading

from pyhttpd.adapters.metrics import LockingMetricsSink


def test_render_reflects_observations():
    """The sink delegates observations to its registry and renders them."""
    sink = LockingMetricsSink()
    sink.observe_request("GET", "/", 200, 0.01)
    assert b"http_requests_total" in sink.render()


def test_concurrent_observations_are_not_lost():
    """Concurrent writers from many threads all land in the counter."""
    sink = LockingMetricsSink()
    worker_count = 16
    per_worker = 200

    def record() -> None:
        for _ in range(per_worker):
            sink.observe_request("GET", "/", 200, 0.01)

    threads = [threading.Thread(target=record) for _ in range(worker_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    text = sink.render().decode("utf-8")
    expected = worker_count * per_worker
    assert (
        f'http_requests_total{{method="GET",route="/",status="200"}} {expected}' in text
    )


def test_in_flight_balance_under_concurrency():
    """Balanced inc/dec across threads leaves the gauge at zero."""
    sink = LockingMetricsSink()

    def cycle() -> None:
        for _ in range(500):
            sink.inc_in_flight()
            sink.dec_in_flight()

    threads = [threading.Thread(target=cycle) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert "http_in_flight_requests 0" in sink.render().decode("utf-8")

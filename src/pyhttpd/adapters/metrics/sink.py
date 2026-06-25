"""Thread-safe metrics sink wrapping the pure registry behind a lock."""

import threading

from pyhttpd.application.metrics_registry import MetricsRegistry


class LockingMetricsSink:
    """Serializes registry mutations and rendering with a single lock."""

    def __init__(self) -> None:
        self._registry = MetricsRegistry()
        self._lock = threading.Lock()

    def observe_request(
        self, method: str, route: str, status: int, latency_seconds: float
    ) -> None:
        """Record a completed request and its latency."""
        with self._lock:
            self._registry.observe_request(method, route, status, latency_seconds)

    def inc_error(self, method: str, route: str) -> None:
        """Increment the error counter for a method/route."""
        with self._lock:
            self._registry.inc_error(method, route)

    def inc_rejection(self, kind: str) -> None:
        """Increment the rejection counter for a rejection kind."""
        with self._lock:
            self._registry.inc_rejection(kind)

    def inc_in_flight(self) -> None:
        """Increment the in-flight request gauge."""
        with self._lock:
            self._registry.inc_in_flight()

    def dec_in_flight(self) -> None:
        """Decrement the in-flight request gauge."""
        with self._lock:
            self._registry.dec_in_flight()

    def render(self) -> bytes:
        """Return the Prometheus text exposition for all metrics."""
        with self._lock:
            return self._registry.render()

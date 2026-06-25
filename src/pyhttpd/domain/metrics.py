"""Metrics port and histogram bucket definition."""

from typing import Protocol

HISTOGRAM_BUCKETS_SECONDS: tuple[float, ...] = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)


class MetricsSink(Protocol):
    """Thread-safe collector of request, error, and rejection metrics."""

    def observe_request(
        self, method: str, route: str, status: int, latency_seconds: float
    ) -> None:
        """Record a completed request and its latency."""

    def inc_error(self, method: str, route: str) -> None:
        """Increment the error counter for a method/route."""

    def inc_rejection(self, kind: str) -> None:
        """Increment the rejection counter for a rejection kind."""

    def inc_in_flight(self) -> None:
        """Increment the in-flight request gauge."""

    def dec_in_flight(self) -> None:
        """Decrement the in-flight request gauge."""

    def render(self) -> bytes:
        """Return the Prometheus text exposition for all metrics."""

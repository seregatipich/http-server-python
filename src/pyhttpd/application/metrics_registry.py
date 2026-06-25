"""Pure Prometheus metric state and text exposition encoder."""

from pyhttpd.domain import HISTOGRAM_BUCKETS_SECONDS


def _format_buckets(buckets: tuple[float, ...]) -> list[str]:
    return [
        repr(bucket) if bucket != int(bucket) else str(bucket) for bucket in buckets
    ]


class MetricsRegistry:
    """Holds counters, a latency histogram, and a gauge; renders exposition text."""

    def __init__(self, buckets: tuple[float, ...] = HISTOGRAM_BUCKETS_SECONDS) -> None:
        self._buckets = buckets
        self._bucket_labels = _format_buckets(buckets)
        self._requests: dict[tuple[str, str, str], int] = {}
        self._errors: dict[tuple[str, str], int] = {}
        self._rejections: dict[str, int] = {}
        self._in_flight = 0
        self._hist_buckets: dict[tuple[str, str], list[int]] = {}
        self._hist_sum: dict[tuple[str, str], float] = {}
        self._hist_count: dict[tuple[str, str], int] = {}

    def observe_request(
        self, method: str, route: str, status: int, latency_seconds: float
    ) -> None:
        """Record a completed request and its latency."""
        request_key = (method, route, str(status))
        self._requests[request_key] = self._requests.get(request_key, 0) + 1
        hist_key = (method, route)
        counts = self._hist_buckets.setdefault(hist_key, [0] * len(self._buckets))
        for index, boundary in enumerate(self._buckets):
            if latency_seconds <= boundary:
                counts[index] += 1
        self._hist_sum[hist_key] = self._hist_sum.get(hist_key, 0.0) + latency_seconds
        self._hist_count[hist_key] = self._hist_count.get(hist_key, 0) + 1

    def inc_error(self, method: str, route: str) -> None:
        """Increment the error counter for a method/route."""
        key = (method, route)
        self._errors[key] = self._errors.get(key, 0) + 1

    def inc_rejection(self, kind: str) -> None:
        """Increment the rejection counter for a rejection kind."""
        self._rejections[kind] = self._rejections.get(kind, 0) + 1

    def inc_in_flight(self) -> None:
        """Increment the in-flight request gauge."""
        self._in_flight += 1

    def dec_in_flight(self) -> None:
        """Decrement the in-flight request gauge."""
        self._in_flight -= 1

    def render(self) -> bytes:
        """Return the Prometheus text exposition for all metrics."""
        lines: list[str] = []
        self._render_requests(lines)
        self._render_errors(lines)
        self._render_histogram(lines)
        self._render_in_flight(lines)
        self._render_rejections(lines)
        return ("\n".join(lines) + "\n").encode("utf-8")

    def _render_requests(self, lines: list[str]) -> None:
        lines.append("# HELP http_requests_total Total HTTP requests.")
        lines.append("# TYPE http_requests_total counter")
        for (method, route, status), value in sorted(self._requests.items()):
            labels = f'method="{method}",route="{route}",status="{status}"'
            lines.append(f"http_requests_total{{{labels}}} {value}")

    def _render_errors(self, lines: list[str]) -> None:
        lines.append("# HELP http_request_errors_total Total HTTP request errors.")
        lines.append("# TYPE http_request_errors_total counter")
        for (method, route), value in sorted(self._errors.items()):
            lines.append(
                f'http_request_errors_total{{method="{method}",route="{route}"}} {value}'
            )

    def _render_histogram(self, lines: list[str]) -> None:
        lines.append("# HELP http_request_duration_seconds Request latency in seconds.")
        lines.append("# TYPE http_request_duration_seconds histogram")
        for (method, route), counts in sorted(self._hist_buckets.items()):
            label_prefix = f'method="{method}",route="{route}"'
            for boundary_label, count in zip(self._bucket_labels, counts):
                lines.append(
                    "http_request_duration_seconds_bucket"
                    f'{{{label_prefix},le="{boundary_label}"}} {count}'
                )
            total = self._hist_count[(method, route)]
            lines.append(
                "http_request_duration_seconds_bucket"
                f'{{{label_prefix},le="+Inf"}} {total}'
            )
            lines.append(
                "http_request_duration_seconds_sum"
                f"{{{label_prefix}}} {self._hist_sum[(method, route)]}"
            )
            lines.append(
                f"http_request_duration_seconds_count{{{label_prefix}}} {total}"
            )

    def _render_in_flight(self, lines: list[str]) -> None:
        lines.append("# HELP http_in_flight_requests In-flight HTTP requests.")
        lines.append("# TYPE http_in_flight_requests gauge")
        lines.append(f"http_in_flight_requests {self._in_flight}")

    def _render_rejections(self, lines: list[str]) -> None:
        lines.append("# HELP http_rejections_total Total rejected connections.")
        lines.append("# TYPE http_rejections_total counter")
        for kind, value in sorted(self._rejections.items()):
            lines.append(f'http_rejections_total{{kind="{kind}"}} {value}')

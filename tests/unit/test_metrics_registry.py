"""Unit tests for the pure Prometheus metrics registry."""

from pyhttpd.application.metrics_registry import MetricsRegistry


def _render(registry: MetricsRegistry) -> str:
    return registry.render().decode("utf-8")


def test_request_counter_accumulates_by_labels():
    """Requests are counted per method, route, and status."""
    registry = MetricsRegistry()
    registry.observe_request("GET", "/", 200, 0.01)
    registry.observe_request("GET", "/", 200, 0.02)
    registry.observe_request("POST", "/files/", 201, 0.03)
    text = _render(registry)

    assert 'http_requests_total{method="GET",route="/",status="200"} 2' in text
    assert 'http_requests_total{method="POST",route="/files/",status="201"} 1' in text


def test_histogram_buckets_are_cumulative_with_sum_and_count():
    """Latency observations populate cumulative buckets plus sum and count."""
    registry = MetricsRegistry()
    registry.observe_request("GET", "/", 200, 0.003)
    registry.observe_request("GET", "/", 200, 0.2)
    text = _render(registry)

    assert (
        'http_request_duration_seconds_bucket{method="GET",route="/",le="0.005"} 1'
        in text
    )
    assert (
        'http_request_duration_seconds_bucket{method="GET",route="/",le="0.25"} 2'
        in text
    )
    assert (
        'http_request_duration_seconds_bucket{method="GET",route="/",le="+Inf"} 2'
        in text
    )
    assert 'http_request_duration_seconds_count{method="GET",route="/"} 2' in text
    assert "http_request_duration_seconds_sum" in text


def test_error_counter():
    """Errors increment a dedicated counter keyed by method and route."""
    registry = MetricsRegistry()
    registry.inc_error("GET", "/boom")
    text = _render(registry)
    assert 'http_request_errors_total{method="GET",route="/boom"} 1' in text


def test_in_flight_gauge_moves_up_and_down():
    """The in-flight gauge reflects concurrent request balance."""
    registry = MetricsRegistry()
    registry.inc_in_flight()
    registry.inc_in_flight()
    registry.dec_in_flight()
    text = _render(registry)
    assert "http_in_flight_requests 1" in text


def test_rejection_counter_by_kind():
    """Rejections are counted per kind."""
    registry = MetricsRegistry()
    registry.inc_rejection("rate_limit")
    registry.inc_rejection("rate_limit")
    registry.inc_rejection("connection_global")
    text = _render(registry)
    assert 'http_rejections_total{kind="rate_limit"} 2' in text
    assert 'http_rejections_total{kind="connection_global"} 1' in text


def test_render_includes_help_and_type_lines():
    """Each metric family emits HELP and TYPE metadata."""
    registry = MetricsRegistry()
    registry.observe_request("GET", "/", 200, 0.01)
    text = _render(registry)
    assert "# HELP http_requests_total" in text
    assert "# TYPE http_requests_total counter" in text
    assert "# TYPE http_request_duration_seconds histogram" in text
    assert "# TYPE http_in_flight_requests gauge" in text


def test_render_returns_bytes():
    """The exposition output is bytes for direct socket writing."""
    assert isinstance(MetricsRegistry().render(), bytes)

"""Metrics adapters: thread-safe Prometheus sink."""

from pyhttpd.adapters.metrics.sink import LockingMetricsSink

__all__ = ["LockingMetricsSink"]

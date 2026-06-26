"""Per-phase request timeout configuration."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PhaseTimeouts:
    """Separate deadlines for the header-read, body-read, and handler phases."""

    header_read_seconds: float
    body_read_seconds: float
    handler_seconds: float

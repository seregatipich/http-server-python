"""Concrete runtime adapters: monotonic clock and UUID4 identifiers."""

import time
import uuid


class MonotonicClock:  # pylint: disable=too-few-public-methods
    """Clock port implementation returning monotonic nanosecond readings."""

    def now_ns(self) -> int:
        """Return the current monotonic time in nanoseconds."""
        return time.monotonic_ns()


class Uuid4IdGenerator:  # pylint: disable=too-few-public-methods
    """Identifier port implementation producing random UUID4 strings."""

    def new_id(self) -> str:
        """Return a new random UUID4 identifier as a string."""
        return str(uuid.uuid4())

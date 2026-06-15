"""Concrete clock adapter backed by the monotonic system clock."""

import time


class MonotonicClock:  # pylint: disable=too-few-public-methods
    """Clock port implementation returning monotonic nanosecond readings."""

    def now_ns(self) -> int:
        """Return the current monotonic time in nanoseconds."""
        return time.monotonic_ns()

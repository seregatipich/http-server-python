"""Pure single-range HTTP Range header parsing."""

from dataclasses import dataclass
from typing import Union


@dataclass(frozen=True)
class ByteRange:
    """An inclusive byte range within a file."""

    start: int
    end: int

    @property
    def length(self) -> int:
        """Return the number of bytes covered by the range."""
        return self.end - self.start + 1


class _Unsatisfiable:
    """Sentinel marking a syntactically valid but unsatisfiable range."""


UNSATISFIABLE_RANGE = _Unsatisfiable()

RangeResult = Union[None, ByteRange, _Unsatisfiable]


def parse_range(header_value: str, file_size: int) -> RangeResult:
    """Parse a single byte range, returning None for full, or unsatisfiable."""
    value = header_value.strip()
    if not value.startswith("bytes="):
        return None
    spec = value[len("bytes=") :]
    if "," in spec:
        return None
    start_text, sep, end_text = spec.partition("-")
    if not sep:
        return None

    if not start_text:
        return _suffix_range(end_text, file_size)
    return _bounded_range(start_text, end_text, file_size)


def _suffix_range(end_text: str, file_size: int) -> RangeResult:
    if not end_text.isdigit():
        return None
    suffix = int(end_text)
    if suffix == 0:
        return UNSATISFIABLE_RANGE
    start = max(0, file_size - suffix)
    return ByteRange(start, file_size - 1)


def _bounded_range(start_text: str, end_text: str, file_size: int) -> RangeResult:
    if not start_text.isdigit():
        return None
    start = int(start_text)
    if start >= file_size:
        return UNSATISFIABLE_RANGE
    if not end_text:
        return ByteRange(start, file_size - 1)
    if not end_text.isdigit():
        return None
    end = min(int(end_text), file_size - 1)
    if end < start:
        return UNSATISFIABLE_RANGE
    return ByteRange(start, end)

"""Unit tests for the HTTP Range header parser."""

from pyhttpd.domain import UNSATISFIABLE_RANGE, ByteRange, parse_range


def test_no_range_header_returns_none():
    """A missing or empty range yields None (serve full body)."""
    assert parse_range("", 100) is None


def test_closed_range():
    """A closed range maps to inclusive start/end with correct length."""
    result = parse_range("bytes=0-3", 100)
    assert result == ByteRange(0, 3)
    assert result.length == 4


def test_open_ended_range_clamps_to_end():
    """An open range runs to the last byte."""
    assert parse_range("bytes=10-", 100) == ByteRange(10, 99)


def test_suffix_range_returns_last_n_bytes():
    """A suffix range returns the final N bytes."""
    assert parse_range("bytes=-20", 100) == ByteRange(80, 99)


def test_end_beyond_size_is_clamped():
    """An end past EOF is clamped to the last byte."""
    assert parse_range("bytes=50-999", 100) == ByteRange(50, 99)


def test_unsatisfiable_when_start_past_end():
    """A start at or beyond the file size is unsatisfiable."""
    assert parse_range("bytes=100-", 100) is UNSATISFIABLE_RANGE
    assert parse_range("bytes=200-300", 100) is UNSATISFIABLE_RANGE


def test_suffix_range_on_empty_file_is_unsatisfiable():
    """A suffix range against a zero-length file is unsatisfiable, not a 206."""
    assert parse_range("bytes=-5", 0) is UNSATISFIABLE_RANGE


def test_bounded_range_on_empty_file_is_unsatisfiable():
    """A bounded range against a zero-length file is unsatisfiable."""
    assert parse_range("bytes=0-0", 0) is UNSATISFIABLE_RANGE


def test_multi_range_falls_back_to_full():
    """Multi-range requests fall back to a full 200 response."""
    assert parse_range("bytes=0-1,3-4", 100) is None


def test_malformed_range_falls_back_to_full():
    """A malformed range header is ignored (full response)."""
    assert parse_range("items=0-1", 100) is None
    assert parse_range("bytes=abc", 100) is None

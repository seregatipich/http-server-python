"""Unit tests covering connection close heuristics."""

from main import should_close


def test_should_close_false_by_default():
    """Ensures default responses keep the connection open."""
    assert not should_close({})
    assert not should_close({"connection": "keep-alive"})


def test_should_close_true_when_header_requests_close():
    """Honors explicit close headers regardless of casing."""
    assert should_close({"connection": "close"})
    assert should_close({"connection": "Close"})

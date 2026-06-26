"""Unit tests for file caching metadata helpers."""

from pyhttpd.domain import compute_etag, http_date, is_not_modified, parse_http_date


def test_compute_etag_is_deterministic_and_quoted():
    """The ETag is stable for the same size/mtime and double-quoted."""
    etag = compute_etag(100, 1_700_000_000_000_000_000)
    assert etag == compute_etag(100, 1_700_000_000_000_000_000)
    assert etag.startswith('"') and etag.endswith('"')


def test_compute_etag_changes_with_inputs():
    """Different size or mtime yields a different ETag."""
    base = compute_etag(100, 1_000)
    assert compute_etag(101, 1_000) != base
    assert compute_etag(100, 1_001) != base


def test_http_date_round_trips():
    """An epoch formatted as an HTTP date parses back to the same second."""
    epoch = 1_700_000_000.0
    parsed = parse_http_date(http_date(epoch))
    assert parsed == epoch


def test_parse_http_date_rejects_garbage():
    """Unparseable date strings return None."""
    assert parse_http_date("not-a-date") is None


def test_is_not_modified_matches_etag():
    """A matching If-None-Match marks the response not modified."""
    etag = compute_etag(10, 20)
    assert is_not_modified(etag, 1000.0, {"if-none-match": etag})
    assert is_not_modified(etag, 1000.0, {"if-none-match": "*"})
    assert not is_not_modified(etag, 1000.0, {"if-none-match": '"other"'})


def test_is_not_modified_handles_weak_and_lists():
    """Weak validators and comma lists are honored in If-None-Match."""
    etag = compute_etag(10, 20)
    assert is_not_modified(etag, 1000.0, {"if-none-match": f"W/{etag}"})
    assert is_not_modified(etag, 1000.0, {"if-none-match": f'"x", {etag}'})


def test_is_not_modified_handles_fractional_mtime():
    """If-Modified-Since compares at whole-second resolution (matches Last-Modified)."""
    fractional = 1_700_000_000.654
    echoed = http_date(fractional)  # truncated to whole seconds
    assert is_not_modified(
        compute_etag(1, 2), fractional, {"if-modified-since": echoed}
    )


def test_is_not_modified_uses_modified_since_when_no_etag_header():
    """If-Modified-Since returns not-modified when file is older or equal."""
    last_modified = 1_700_000_000.0
    older_request = {"if-modified-since": http_date(last_modified)}
    assert is_not_modified(compute_etag(1, 2), last_modified, older_request)
    newer_request = {"if-modified-since": http_date(last_modified - 10)}
    assert not is_not_modified(compute_etag(1, 2), last_modified, newer_request)

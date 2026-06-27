"""Unit tests for query-string and form-body parsing (F3)."""

import pytest

from pyhttpd.domain.forms import parse_multipart, parse_query, parse_urlencoded

MULTIPART_BODY = (
    b"--BOUNDARY\r\n"
    b'Content-Disposition: form-data; name="field1"\r\n\r\n'
    b"value1\r\n"
    b"--BOUNDARY\r\n"
    b'Content-Disposition: form-data; name="file1"; filename="a.txt"\r\n'
    b"Content-Type: text/plain\r\n\r\n"
    b"file-content\r\n"
    b"--BOUNDARY--\r\n"
)


def test_parse_query_groups_repeated_keys() -> None:
    assert parse_query("a=1&a=2&b=3") == {"a": ["1", "2"], "b": ["3"]}


def test_parse_query_keeps_blank_values() -> None:
    assert parse_query("flag=&x=1") == {"flag": [""], "x": ["1"]}


def test_parse_query_decodes_percent_and_plus() -> None:
    assert parse_query("q=a+b%20c") == {"q": ["a b c"]}


def test_parse_query_empty_string() -> None:
    assert parse_query("") == {}


def test_parse_query_enforces_field_cap() -> None:
    with pytest.raises(ValueError):
        parse_query("&".join(f"k{i}=1" for i in range(5)), max_fields=3)


def test_parse_urlencoded_basic() -> None:
    assert parse_urlencoded(b"name=jane&role=admin") == {
        "name": ["jane"],
        "role": ["admin"],
    }


def test_parse_urlencoded_rejects_invalid_utf8() -> None:
    with pytest.raises(ValueError):
        parse_urlencoded(b"name=\xff\xfe")


def test_parse_multipart_extracts_fields_and_files() -> None:
    parts = parse_multipart(MULTIPART_BODY, "multipart/form-data; boundary=BOUNDARY")

    by_name = {part.name: part for part in parts}
    assert set(by_name) == {"field1", "file1"}
    assert by_name["field1"].content == b"value1"
    assert by_name["field1"].filename is None
    assert by_name["file1"].filename == "a.txt"
    assert by_name["file1"].content == b"file-content"
    assert by_name["file1"].content_type == "text/plain"


def test_parse_multipart_rejects_non_multipart() -> None:
    with pytest.raises(ValueError):
        parse_multipart(b"irrelevant", "application/json")


def test_parse_multipart_enforces_part_cap() -> None:
    with pytest.raises(ValueError):
        parse_multipart(
            MULTIPART_BODY, "multipart/form-data; boundary=BOUNDARY", max_parts=1
        )

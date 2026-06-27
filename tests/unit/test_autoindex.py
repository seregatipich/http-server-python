"""Unit tests for the directory autoindex (F10)."""

import pytest

from pyhttpd.application.handlers.autoindex import _render_html, render_autoindex
from pyhttpd.application.handlers.files import make_files_handler
from pyhttpd.domain import FileServingOptions, NotFound
from tests.unit._helpers import RecordingLogger, make_context, make_request


def test_render_autoindex_lists_files_and_dirs(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("x")
    (tmp_path / "sub").mkdir()
    response = render_autoindex(make_request(path="/files/dir"), tmp_path, None)

    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.headers["Content-Type"] == "text/html; charset=utf-8"
    body = response.body.decode()
    assert "a.txt" in body
    assert "sub/" in body
    assert 'href="/files/dir/sub/"' in body


def test_render_html_escapes_entry_names() -> None:
    document = _render_html("/files/dir", [("<script>.txt", False, 5, 0.0)])
    assert "<script>.txt" not in document
    assert "&lt;script&gt;.txt" in document


def test_render_html_includes_parent_link_for_subdir() -> None:
    assert "../" in _render_html("/files/sub", [])


def test_render_html_root_has_no_parent_link() -> None:
    assert "../" not in _render_html("/files/", [])


def test_files_handler_directory_404_when_autoindex_off(tmp_path) -> None:
    (tmp_path / "docs").mkdir()
    handler = make_files_handler(
        str(tmp_path), RecordingLogger(), None, FileServingOptions(autoindex=False)
    )
    with pytest.raises(NotFound):
        handler(make_request(path="/files/docs"), make_context())


def test_files_handler_directory_listed_when_autoindex_on(tmp_path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.txt").write_text("x")
    handler = make_files_handler(
        str(tmp_path), RecordingLogger(), None, FileServingOptions(autoindex=True)
    )
    response = handler(make_request(path="/files/docs"), make_context())
    assert response.status_line == "HTTP/1.1 200 OK"
    assert b"a.txt" in response.body

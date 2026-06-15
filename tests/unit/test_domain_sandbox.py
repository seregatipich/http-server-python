"""Unit tests for the filesystem sandbox path resolver."""

import pytest

from pyhttpd.domain.errors import ForbiddenPath
from pyhttpd.domain.sandbox import resolve_sandbox_path


def test_valid_file_resolves_inside_root(tmp_path):
    """A simple file path resolves to a location under the sandbox root."""
    (tmp_path / "index.html").write_text("ok")
    resolved = resolve_sandbox_path(str(tmp_path), "index.html")
    assert resolved == (tmp_path / "index.html").resolve()


def test_valid_nested_file_resolves_inside_root(tmp_path):
    """A nested path resolves under the sandbox root."""
    nested = tmp_path / "assets" / "css"
    nested.mkdir(parents=True)
    (nested / "site.css").write_text("body{}")
    resolved = resolve_sandbox_path(str(tmp_path), "assets/css/site.css")
    assert resolved == (nested / "site.css").resolve()


def test_resolved_path_stays_under_root(tmp_path):
    """The resolved path is contained within the sandbox root."""
    (tmp_path / "page.html").write_text("data")
    resolved = resolve_sandbox_path(str(tmp_path), "page.html")
    assert tmp_path.resolve() in resolved.parents


def test_leading_slash_is_anchored_to_root(tmp_path):
    """A leading slash is stripped and the path is anchored to the root."""
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("local")
    resolved = resolve_sandbox_path(str(tmp_path), "/etc/passwd")
    assert resolved == (tmp_path / "etc" / "passwd").resolve()
    assert tmp_path.resolve() in resolved.parents


def test_nonexistent_file_inside_root_still_resolves(tmp_path):
    """A path to a missing file inside the root resolves without raising."""
    resolved = resolve_sandbox_path(str(tmp_path), "missing.html")
    assert resolved == (tmp_path / "missing.html").resolve()


def test_dotdot_traversal_raises(tmp_path):
    """A path containing a parent reference is rejected."""
    with pytest.raises(ForbiddenPath):
        resolve_sandbox_path(str(tmp_path), "../secret.txt")


def test_embedded_dotdot_traversal_raises(tmp_path):
    """A parent reference nested within a path is rejected."""
    with pytest.raises(ForbiddenPath):
        resolve_sandbox_path(str(tmp_path), "assets/../../secret.txt")


def test_absolute_path_escape_attempt_raises(tmp_path):
    """An absolute escape combined with traversal is rejected."""
    with pytest.raises(ForbiddenPath):
        resolve_sandbox_path(str(tmp_path), "/../../../../etc/passwd")


def test_nul_byte_raises(tmp_path):
    """A path containing a NUL byte is rejected before any resolution."""
    with pytest.raises(ForbiddenPath):
        resolve_sandbox_path(str(tmp_path), "index.html\x00.png")


def test_empty_path_raises(tmp_path):
    """An empty user path is rejected."""
    with pytest.raises(ForbiddenPath):
        resolve_sandbox_path(str(tmp_path), "")


def test_root_only_slash_raises(tmp_path):
    """A path consisting solely of slashes reduces to empty and is rejected."""
    with pytest.raises(ForbiddenPath):
        resolve_sandbox_path(str(tmp_path), "///")


def test_symlink_escaping_root_raises(tmp_path):
    """A symlink whose target leaves the root is rejected after resolution."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret = outside_dir / "secret.txt"
    secret.write_text("classified")

    sandbox_root = tmp_path / "sandbox"
    sandbox_root.mkdir()
    escape_link = sandbox_root / "escape"
    escape_link.symlink_to(secret)

    with pytest.raises(ForbiddenPath):
        resolve_sandbox_path(str(sandbox_root), "escape")


def test_symlink_inside_root_resolves(tmp_path):
    """A symlink whose target stays inside the root is permitted."""
    sandbox_root = tmp_path / "sandbox"
    sandbox_root.mkdir()
    real_file = sandbox_root / "real.txt"
    real_file.write_text("inside")
    inside_link = sandbox_root / "alias"
    inside_link.symlink_to(real_file)

    resolved = resolve_sandbox_path(str(sandbox_root), "alias")
    assert resolved == real_file.resolve()
    assert sandbox_root.resolve() in resolved.parents


def test_root_itself_is_permitted_via_dot_collapse(tmp_path):
    """A path that resolves to the root directory itself is accepted."""
    (tmp_path / "child").mkdir()
    resolved = resolve_sandbox_path(str(tmp_path), "child/.")
    assert resolved == (tmp_path / "child").resolve()

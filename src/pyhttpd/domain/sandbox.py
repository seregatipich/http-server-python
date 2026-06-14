"""Filesystem sandbox utilities for safe path resolution."""

from pathlib import Path


class ForbiddenPath(Exception):
    """Raised when a requested path escapes the configured sandbox."""


def resolve_sandbox_path(directory: str, user_path: str) -> Path:
    """Resolve a user-supplied path inside the configured sandbox."""
    if "\x00" in user_path:
        raise ForbiddenPath

    directory_root = Path(directory).resolve()
    relative_part = user_path.lstrip("/")
    if not relative_part:
        raise ForbiddenPath

    if ".." in Path(relative_part).parts:
        raise ForbiddenPath

    target = (directory_root / relative_part).resolve()
    if not (target == directory_root or directory_root in target.parents):
        raise ForbiddenPath

    return target

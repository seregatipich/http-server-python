"""Authenticated principal and role-based access policy."""

from dataclasses import dataclass
from typing import Optional

DEFAULT_AUTH_MODE = "none"

RBAC_POLICY: tuple[tuple[str, str, str], ...] = (
    ("/files", "GET", "files:read"),
    ("/files", "POST", "files:write"),
)


@dataclass(frozen=True)
class Principal:
    """An authenticated caller and the scopes it was granted."""

    identity: str
    scopes: frozenset[str]

    def has_scope(self, scope: str) -> bool:
        """Return whether the principal holds the given scope."""
        return scope in self.scopes


def required_scope(path: str, method: str) -> Optional[str]:
    """Return the scope required to access a path/method, or None if open."""
    for prefix, verb, scope in RBAC_POLICY:
        if method == verb and (path == prefix or path.startswith(prefix + "/")):
            return scope
    return None

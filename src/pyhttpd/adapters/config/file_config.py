"""TOML config-file overlay and reload support (stdlib tomllib)."""

import tomllib
from argparse import Namespace
from typing import Any, Dict, List


def load_config_file(path: str) -> Dict[str, Any]:
    """Load a TOML config file, normalizing keys to argparse dest names."""
    with open(path, "rb") as handle:
        data = tomllib.load(handle)
    return {key.replace("-", "_"): value for key, value in data.items()}


def apply_overlay(
    namespace: Namespace, overlay: Dict[str, Any], argv: List[str]
) -> None:
    """Apply file values where the matching CLI flag was not explicitly passed."""
    for key, value in overlay.items():
        if hasattr(namespace, key) and not _explicitly_passed(argv, key):
            setattr(namespace, key, value)


def reapply_overlay(namespace: Namespace, overlay: Dict[str, Any]) -> None:
    """Re-apply file values onto the namespace (used on SIGHUP reload)."""
    for key, value in overlay.items():
        if hasattr(namespace, key):
            setattr(namespace, key, value)


def _explicitly_passed(argv: List[str], dest: str) -> bool:
    flag = "--" + dest.replace("_", "-")
    negated = "--no-" + dest.replace("_", "-")
    return any(
        token in (flag, negated)
        or token.startswith(f"{flag}=")
        or token.startswith(f"{negated}=")
        for token in argv
    )

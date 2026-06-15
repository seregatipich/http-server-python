"""Backward-compatibility shim; ServerLifecycle now lives in adapters."""

from pyhttpd.adapters.lifecycle import ServerLifecycle

__all__ = ["ServerLifecycle"]

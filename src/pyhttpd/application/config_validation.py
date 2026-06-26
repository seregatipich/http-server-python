"""Fail-fast validation of startup configuration."""

import argparse
import os


def _validate_timeouts(args: argparse.Namespace) -> list[str]:
    errors = []
    for name in (
        "socket_timeout",
        "header_read_timeout",
        "body_read_timeout",
        "handler_timeout",
    ):
        value = getattr(args, name, 1)
        if value <= 0:
            errors.append(f"{name.replace('_', '-')} must be a positive timeout")
    return errors


def _validate_tls(args: argparse.Namespace) -> list[str]:
    if bool(args.cert) != bool(args.key):
        return ["TLS requires both --cert and --key, or neither"]
    errors = []
    for path in (args.cert, args.key):
        if path and not os.access(path, os.R_OK):
            errors.append(f"TLS file is not readable: {path}")
    return errors


def _validate_auth(args: argparse.Namespace) -> list[str]:
    if args.auth_mode == "api-key" and not args.auth_credentials:
        return ["auth-mode api-key requires --auth-credentials"]
    if args.auth_mode == "jwt" and not args.jwt_secret:
        return ["auth-mode jwt requires a --jwt-secret"]
    return []


def validate_startup_config(args: argparse.Namespace) -> list[str]:
    """Return a list of human-readable configuration errors, empty if valid."""
    errors = []
    if not 0 <= args.port <= 65535:
        errors.append(f"port must be between 0 and 65535, got {args.port}")
    errors.extend(_validate_timeouts(args))
    errors.extend(_validate_tls(args))
    errors.extend(_validate_auth(args))
    return errors

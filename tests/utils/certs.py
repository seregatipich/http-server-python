"""Generate a CA + signed server/client certificates via openssl for TLS tests."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple


def openssl_available() -> bool:
    """Return whether the openssl CLI is on PATH."""
    return shutil.which("openssl") is not None


def _run(*args: str) -> None:
    subprocess.run(args, check=True, capture_output=True)


def generate_ca(directory: Path) -> Tuple[Path, Path]:
    """Create a self-signed CA certificate and key."""
    ca_key = directory / "ca.key"
    ca_crt = directory / "ca.crt"
    _run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_crt),
        "-days",
        "1",
        "-subj",
        "/CN=pyhttpd Test CA",
    )
    return ca_crt, ca_key


def generate_signed_cert(
    directory: Path,
    name: str,
    common_name: str,
    ca_crt: Path,
    ca_key: Path,
    san: Optional[str] = None,
) -> Tuple[Path, Path]:
    """Create a certificate/key signed by the CA, optionally with a SAN."""
    key = directory / f"{name}.key"
    csr = directory / f"{name}.csr"
    crt = directory / f"{name}.crt"
    _run(
        "openssl",
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(csr),
        "-subj",
        f"/CN={common_name}",
    )
    sign = [
        "openssl",
        "x509",
        "-req",
        "-in",
        str(csr),
        "-CA",
        str(ca_crt),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(crt),
        "-days",
        "1",
    ]
    if san is not None:
        extension = directory / f"{name}.ext"
        extension.write_text(f"subjectAltName={san}\n")
        sign += ["-extfile", str(extension)]
    _run(*sign)
    return crt, key

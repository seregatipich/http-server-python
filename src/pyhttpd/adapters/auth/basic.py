"""HTTP Basic authentication adapter using hashed-password comparison."""

import base64
import binascii
import hashlib
import hmac
from typing import Mapping, Optional

from pyhttpd.domain import AuthConfig, Principal


class BasicAuthenticator:
    """Authenticates `Authorization: Basic base64(user:pass)` against hashes.

    Only the SHA-256 hex of each password is stored (mirroring the api-key
    adapter), and comparison is constant-time. Credentials should only ride
    over TLS; Basic transmits the password reversibly on every request.
    """

    def __init__(self, config: AuthConfig) -> None:
        self._credentials = config.credentials
        self._roles = config.roles

    @property
    def challenge(self) -> str:
        """Return the Basic WWW-Authenticate challenge."""
        return 'Basic realm="pyhttpd"'

    def authenticate(self, headers: Mapping[str, str]) -> Optional[Principal]:
        """Return the principal for valid credentials, or None."""
        header = headers.get("authorization", "")
        scheme, _, encoded = header.partition(" ")
        if scheme.lower() != "basic" or not encoded:
            return None
        identity, password = _decode_credentials(encoded)
        if identity is None:
            return None
        stored_hash = self._credentials.get(identity)
        if stored_hash is None:
            return None
        presented_hash = hashlib.sha256(password.encode()).hexdigest()
        if not hmac.compare_digest(presented_hash, stored_hash):
            return None
        scopes = frozenset(self._roles.get(identity, ()))
        return Principal(identity=identity, scopes=scopes)


def _decode_credentials(encoded: str) -> tuple[Optional[str], str]:
    try:
        raw = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError):
        return None, ""
    identity, separator, password = raw.partition(":")
    if not separator:
        return None, ""
    return identity, password

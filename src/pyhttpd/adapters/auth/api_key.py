"""API-key authentication adapter using hashed-key comparison."""

import hashlib
import hmac
from typing import Mapping, Optional

from pyhttpd.domain import AuthConfig, Principal


class ApiKeyAuthenticator:
    """Authenticates `Authorization: ApiKey <key>` against stored hashes."""

    def __init__(self, config: AuthConfig) -> None:
        self._credentials = config.credentials
        self._roles = config.roles

    @property
    def challenge(self) -> str:
        """Return the ApiKey WWW-Authenticate challenge."""
        return 'ApiKey realm="pyhttpd"'

    def authenticate(self, headers: Mapping[str, str]) -> Optional[Principal]:
        """Return the principal for a recognized key, or None."""
        header = headers.get("authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "apikey" or not presented:
            return None
        presented_hash = hashlib.sha256(presented.encode()).hexdigest()
        for identity, stored_hash in self._credentials.items():
            if hmac.compare_digest(presented_hash, stored_hash):
                scopes = frozenset(self._roles.get(identity, ()))
                return Principal(identity=identity, scopes=scopes)
        return None

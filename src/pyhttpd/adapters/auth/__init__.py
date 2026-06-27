"""Authentication adapters: api-key, HTTP Basic, and hand-rolled HS256 JWT."""

from pyhttpd.adapters.auth.api_key import ApiKeyAuthenticator
from pyhttpd.adapters.auth.basic import BasicAuthenticator
from pyhttpd.adapters.auth.jwt import JwtAuthenticator, decode_hs256

__all__ = [
    "ApiKeyAuthenticator",
    "BasicAuthenticator",
    "JwtAuthenticator",
    "decode_hs256",
]

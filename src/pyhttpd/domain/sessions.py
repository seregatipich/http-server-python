"""HMAC-signed session cookie tokens.

A token is ``<session_id>.<signature>`` where the signature is the URL-safe
base64 of HMAC-SHA256(secret, session_id). Verification is constant-time, so a
tampered identifier or signature is rejected without leaking timing.
"""

import base64
import hashlib
import hmac
from typing import Optional


def sign(session_id: str, secret: str) -> str:
    """Return a signed cookie token for the session id."""
    return f"{session_id}.{_signature(session_id, secret)}"


def verify(token: str, secret: str) -> Optional[str]:
    """Return the session id when the token's signature is valid, else None."""
    session_id, separator, signature = token.rpartition(".")
    if not separator or not session_id:
        return None
    if not hmac.compare_digest(signature, _signature(session_id, secret)):
        return None
    return session_id


def _signature(session_id: str, secret: str) -> str:
    digest = hmac.new(secret.encode(), session_id.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

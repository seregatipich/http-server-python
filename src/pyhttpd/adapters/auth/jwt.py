"""Hand-rolled HS256 JWT verification with zero runtime dependencies."""

import base64
import hashlib
import hmac
import json
import time
from typing import Callable, Mapping, Optional

from pyhttpd.domain import AuthConfig, Principal


class InvalidToken(Exception):
    """Raised when a JWT fails structural, signature, or claim validation."""


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (ValueError, TypeError) as error:
        raise InvalidToken("malformed base64url segment") from error


def _decode_json(segment: str) -> dict:
    try:
        decoded = json.loads(_b64url_decode(segment))
    except json.JSONDecodeError as error:
        raise InvalidToken("invalid JSON segment") from error
    if not isinstance(decoded, dict):
        raise InvalidToken("segment is not a JSON object")
    return decoded


def _verify_signature(signing_input: str, signature: str, secret: str) -> None:
    expected = hmac.new(
        secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected, _b64url_decode(signature)):
        raise InvalidToken("signature mismatch")


def _validate_claims(
    claims: dict,
    *,
    issuer: Optional[str],
    audience: Optional[str],
    now: int,
) -> None:
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or now >= exp:
        raise InvalidToken("token expired or missing exp")
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and now < nbf:
        raise InvalidToken("token not yet valid")
    if issuer is not None and claims.get("iss") != issuer:
        raise InvalidToken("issuer mismatch")
    if audience is not None:
        aud = claims.get("aud")
        allowed = aud if isinstance(aud, list) else [aud]
        if audience not in allowed:
            raise InvalidToken("audience mismatch")


def decode_hs256(
    token: str,
    secret: str,
    *,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    now: Optional[int] = None,
) -> dict:
    """Verify an HS256 JWT and return its claims, raising on any failure."""
    segments = token.split(".")
    if len(segments) != 3:
        raise InvalidToken("token must have three segments")
    header_segment, payload_segment, signature_segment = segments

    header = _decode_json(header_segment)
    if header.get("alg") != "HS256":
        raise InvalidToken("unsupported algorithm")
    if header.get("typ") not in (None, "JWT"):
        raise InvalidToken("unsupported token type")

    _verify_signature(f"{header_segment}.{payload_segment}", signature_segment, secret)

    claims = _decode_json(payload_segment)
    _validate_claims(
        claims,
        issuer=issuer,
        audience=audience,
        now=int(time.time()) if now is None else now,
    )
    return claims


def _extract_scopes(claims: dict) -> frozenset[str]:
    scope = claims.get("scope")
    if isinstance(scope, str):
        return frozenset(scope.split())
    if isinstance(scope, list):
        return frozenset(str(item) for item in scope)
    return frozenset()


class JwtAuthenticator:
    """Authenticates Bearer JWTs signed with a shared HS256 secret."""

    def __init__(
        self, config: AuthConfig, now: Optional[Callable[[], int]] = None
    ) -> None:
        self._config = config
        self._now = now

    @property
    def challenge(self) -> str:
        """Return the Bearer WWW-Authenticate challenge."""
        return 'Bearer realm="pyhttpd"'

    def authenticate(self, headers: Mapping[str, str]) -> Optional[Principal]:
        """Return the principal for a valid Bearer token, or None."""
        header = headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme != "Bearer" or not token:
            return None
        try:
            claims = decode_hs256(
                token,
                self._config.jwt_secret,
                issuer=self._config.jwt_issuer,
                audience=self._config.jwt_audience,
                now=None if self._now is None else self._now(),
            )
        except InvalidToken:
            return None
        identity = claims.get("sub")
        if not isinstance(identity, str):
            return None
        return Principal(identity=identity, scopes=_extract_scopes(claims))

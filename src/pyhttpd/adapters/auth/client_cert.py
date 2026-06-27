"""Mutual-TLS authentication: map a verified client certificate to a Principal.

The TLS layer has already verified the certificate chain against the configured
CA, so by the time a request is processed the peer identity is trustworthy. This
adapter turns the parsed ``getpeercert()`` dict into a domain Principal and
provides an Authenticator that defers to that transport-supplied identity.
"""

from typing import Any, Mapping, Optional, Sequence

from pyhttpd.domain import AuthConfig, Principal


def principal_from_peercert(
    peercert: Optional[Mapping[str, Any]], roles: Mapping[str, Sequence[str]]
) -> Optional[Principal]:
    """Map a verified client certificate to a Principal, or None when absent."""
    if not peercert:
        return None
    identity = _common_name(peercert) or _first_dns_san(peercert)
    if not identity:
        return None
    return Principal(identity=identity, scopes=frozenset(roles.get(identity, ())))


def _common_name(peercert: Mapping[str, Any]) -> Optional[str]:
    for relative_name in peercert.get("subject", ()):
        for attribute, value in relative_name:
            if attribute == "commonName":
                return str(value)
    return None


def _first_dns_san(peercert: Mapping[str, Any]) -> Optional[str]:
    for kind, value in peercert.get("subjectAltName", ()):
        if kind == "DNS":
            return str(value)
    return None


class ClientCertAuthenticator:
    """Authenticator whose identity comes from the mutual-TLS client cert.

    Header credentials are never consulted; the auth middleware uses the
    transport-supplied principal set on the request context. This class exists so
    ``--auth-mode client-cert`` registers the enforcement middleware.
    """

    def __init__(self, config: AuthConfig) -> None:
        self._roles = config.roles

    @property
    def challenge(self) -> str:
        """Return a placeholder challenge (clients authenticate via TLS)."""
        return "ClientCert"

    def authenticate(self, _headers: Mapping[str, str]) -> Optional[Principal]:
        """Always None; the cert principal is supplied by the transport."""
        return None

"""Integration tests for TLS SNI multi-cert and mutual TLS (F12)."""

from __future__ import annotations

import socket
import ssl
from pathlib import Path
from typing import Optional

import pytest
import requests
import urllib3

from tests.conftest import _launch_server
from tests.utils.certs import generate_ca, generate_signed_cert, openssl_available
from tests.utils.http import reserve_port

pytestmark = pytest.mark.integration

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if not openssl_available():
    pytest.skip("openssl not available", allow_module_level=True)

HOST = "127.0.0.1"


def _served_common_name(port: int, server_hostname: str, ca_crt: Path) -> Optional[str]:
    context = ssl.create_default_context(cafile=str(ca_crt))
    context.check_hostname = False
    with socket.create_connection((HOST, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=server_hostname) as tls:
            cert = tls.getpeercert() or {}
    for relative_name in cert.get("subject", ()):
        for attribute, value in relative_name:
            if attribute == "commonName":
                return value
    return None


@pytest.fixture(name="sni_server")
def _sni_server(tmp_path_factory):
    certs = tmp_path_factory.mktemp("sni-certs")
    ca_crt, ca_key = generate_ca(certs)
    default_crt, default_key = generate_signed_cert(
        certs, "default", "localhost", ca_crt, ca_key, san="IP:127.0.0.1"
    )
    a_crt, a_key = generate_signed_cert(
        certs, "a", "a.test", ca_crt, ca_key, san="DNS:a.test"
    )
    b_crt, b_key = generate_signed_cert(
        certs, "b", "b.test", ca_crt, ca_key, san="DNS:b.test"
    )
    port = reserve_port(HOST)
    directory = tmp_path_factory.mktemp("sni-files")
    args = [
        "--cert",
        str(default_crt),
        "--key",
        str(default_key),
        "--tls-sni",
        f"a.test:{a_crt}:{a_key}",
        "--tls-sni",
        f"b.test:{b_crt}:{b_key}",
    ]
    generator = _launch_server(
        HOST, port, directory, args, log_file=directory / "server.log"
    )
    next(generator)
    try:
        yield {"port": port, "ca": ca_crt}
    finally:
        try:
            next(generator)
        except StopIteration:
            pass


@pytest.fixture(name="mtls_server")
def _mtls_server(tmp_path_factory):
    certs = tmp_path_factory.mktemp("mtls-certs")
    ca_crt, ca_key = generate_ca(certs)
    server_crt, server_key = generate_signed_cert(
        certs, "server", "localhost", ca_crt, ca_key, san="IP:127.0.0.1"
    )
    writer_crt, writer_key = generate_signed_cert(
        certs, "writer", "writer", ca_crt, ca_key
    )
    reader_crt, reader_key = generate_signed_cert(
        certs, "reader", "reader", ca_crt, ca_key
    )
    port = reserve_port(HOST)
    directory = tmp_path_factory.mktemp("mtls-files")
    args = [
        "--cert",
        str(server_crt),
        "--key",
        str(server_key),
        "--tls-client-ca",
        str(ca_crt),
        "--tls-require-client-cert",
        "--auth-mode",
        "client-cert",
        "--auth-roles",
        "writer:files:read|files:write, reader:files:read",
    ]
    generator = _launch_server(
        HOST, port, directory, args, log_file=directory / "server.log"
    )
    next(generator)
    try:
        yield {
            "port": port,
            "writer": (str(writer_crt), str(writer_key)),
            "reader": (str(reader_crt), str(reader_key)),
        }
    finally:
        try:
            next(generator)
        except StopIteration:
            pass


def test_sni_serves_per_host_certificate(sni_server) -> None:
    port, ca = sni_server["port"], sni_server["ca"]
    assert _served_common_name(port, "a.test", ca) == "a.test"
    assert _served_common_name(port, "b.test", ca) == "b.test"
    assert _served_common_name(port, "unknown.test", ca) == "localhost"


def test_mtls_writer_cert_can_write(mtls_server) -> None:
    url = f"https://{HOST}:{mtls_server['port']}/files/created.txt"
    response = requests.post(
        url, cert=mtls_server["writer"], data=b"payload", verify=False, timeout=5
    )
    assert response.status_code == 201


def test_mtls_reader_cert_forbidden_from_write(mtls_server) -> None:
    url = f"https://{HOST}:{mtls_server['port']}/files/blocked.txt"
    response = requests.post(
        url, cert=mtls_server["reader"], data=b"payload", verify=False, timeout=5
    )
    assert response.status_code == 403


def test_mtls_without_client_cert_is_rejected(mtls_server) -> None:
    url = f"https://{HOST}:{mtls_server['port']}/files/x"
    with pytest.raises(requests.exceptions.RequestException):
        requests.get(url, verify=False, timeout=5)

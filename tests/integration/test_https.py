"""Integration tests for HTTPS/TLS support and security headers."""

import os
import subprocess
import time
from collections.abc import Iterator
from typing import Final

import pytest
import requests

pytestmark = pytest.mark.filterwarnings("ignore::urllib3.exceptions.InsecureRequestWarning")

# Constants for the test server
HOST: Final[str] = "localhost"
PORT: Final[int] = 4222
CERT_FILE: Final[str] = os.path.abspath("certs/cert.pem")
KEY_FILE: Final[str] = os.path.abspath("certs/key.pem")


@pytest.fixture(scope="module")
def https_server_url() -> Iterator[str]:
    """Start the HTTP server with TLS enabled in a background process."""
    # Ensure certs exist
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        pytest.skip("Certificate or key file missing, skipping HTTPS tests")

    cmd = [
        "python3",
        "main.py",
        "--port",
        str(PORT),
        "--cert",
        CERT_FILE,
        "--key",
        KEY_FILE,
    ]

    # pylint: disable=consider-using-with
    process: subprocess.Popen[str] = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    # Wait for server to start
    time.sleep(2)

    yield f"https://{HOST}:{PORT}"

    process.terminate()
    process.wait()


def test_https_connection(
    https_server_url: str,
):  # pylint: disable=redefined-outer-name
    """Verify that the server accepts HTTPS connections."""
    response = requests.get(f"{https_server_url}/", verify=False, timeout=5)
    assert response.status_code == 200


def test_security_headers(
    https_server_url: str,
):  # pylint: disable=redefined-outer-name
    """Verify that security headers are present in the response."""
    response = requests.get(f"{https_server_url}/", verify=False, timeout=5)
    assert response.status_code == 200

    headers = response.headers
    assert (
        headers.get("Strict-Transport-Security")
        == "max-age=63072000; includeSubDomains"
    )
    assert headers.get("Content-Security-Policy") == "default-src 'self'"
    assert headers.get("X-Content-Type-Options") == "nosniff"


def test_http_connection_fails() -> None:
    """Verify that plain HTTP requests to the HTTPS port fail."""
    # This is expected to fail at the SSL handshake level or return a connection error
    with pytest.raises(requests.exceptions.RequestException):
        requests.get(f"http://{HOST}:{PORT}/", timeout=1)


def test_files_endpoint_headers(
    https_server_url: str,
):  # pylint: disable=redefined-outer-name
    """Verify security headers on file responses."""
    # We need to ensure we can hit the files endpoint.
    # The server defaults to current directory.
    # Let's try to get the LICENSE file which we know exists in root.

    # Since we are running from root, LICENSE should be available at /files/LICENSE
    response = requests.get(
        f"{https_server_url}/files/LICENSE", verify=False, timeout=5
    )

    # If the file exists, check headers.
    # If not (maybe 404), check headers anyway as we added them to 404 too.
    headers = response.headers
    assert (
        headers.get("Strict-Transport-Security")
        == "max-age=63072000; includeSubDomains"
    )
    assert headers.get("Content-Security-Policy") == "default-src 'self'"
    assert headers.get("X-Content-Type-Options") == "nosniff"

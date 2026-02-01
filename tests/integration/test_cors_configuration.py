import pytest
import requests

from tests.conftest import _launch_server, reserve_port


@pytest.fixture(name="cors_server")
def _cors_server(tmp_path):
    host = "127.0.0.1"
    port = reserve_port(host)
    log_file = tmp_path / "server.log"

    # Configure server with specific allowed origin and credentials enabled
    extra_args = [
        "--cors-allowed-origins",
        "https://app.example.com",
        "--cors-allow-credentials",
    ]

    yield from _launch_server(host, port, tmp_path, extra_args, log_file)


def test_cors_custom_allowlist_with_credentials(cors_server):
    """
    Ensure custom allowlists (non-*) respect credentials by returning
    the caller origin and Vary: Origin when --cors-allow-credentials is enabled.
    """
    base_url = cors_server["base_url"]

    # 1. Allowed origin
    headers = {"Origin": "https://app.example.com"}
    response = requests.get(f"{base_url}/", headers=headers, timeout=5)
    assert response.status_code == 200
    assert (
        response.headers.get("Access-Control-Allow-Origin") == "https://app.example.com"
    )
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"
    assert response.headers.get("Vary") == "Origin"

    # 2. Disallowed origin
    headers = {"Origin": "https://evil.com"}
    response = requests.get(f"{base_url}/", headers=headers, timeout=5)
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers

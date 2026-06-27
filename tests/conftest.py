"""Shared pytest fixtures for integration and unit tests."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Generator, TypedDict

import pytest

from tests.utils.http import reserve_port, wait_for_port

if TYPE_CHECKING:
    from _pytest.tmpdir import TempPathFactory

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _launch_server(
    host: str,
    port: int,
    directory: Path,
    extra_args: list[str] | None = None,
    log_file: Path | None = None,
) -> Generator[ServerProcessInfo, None, None]:
    args = [
        sys.executable,
        "-m",
        "pyhttpd",
        "--directory",
        str(directory),
        "--host",
        host,
        "--port",
        str(port),
    ]
    if log_file:
        args.extend(["--log-destination", str(log_file)])
    if extra_args:
        args.extend(extra_args)

    with subprocess.Popen(
        args,
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as process:
        try:
            wait_for_port(host, port)
        except Exception:
            # If startup failed, print stdout/stderr to help debug
            stdout, stderr = process.communicate(timeout=1)
            print(f"\nServer stdout:\n{stdout}")
            print(f"\nServer stderr:\n{stderr}")
            process.terminate()
            process.wait(timeout=5)
            raise

        service_url = f"http://{host}:{port}"
        yield {
            "base_url": service_url,
            "host": host,
            "port": port,
            "directory": directory,
            "process": process,
            "log_file": log_file,
        }

        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


class ServerProcessInfo(TypedDict):
    """Metadata describing a running server fixture instance."""

    base_url: str
    host: str
    port: int
    directory: Path
    process: subprocess.Popen[bytes]
    log_file: Path | None


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Expose the repository root path to tests."""

    return PROJECT_ROOT


@pytest.fixture(name="server_process")
def _server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the HTTP server in a background process for integration tests."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files")
    log_file = directory / "server.log"
    yield from _launch_server(host, port, directory, log_file=log_file)


@pytest.fixture(name="limited_server_process")
def _limited_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the HTTP server with strict connection and rate limits for tests."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-limited")
    log_file = directory / "server.log"
    limit_args = [
        "--max-connections",
        "1",
        "--max-connections-per-ip",
        "1",
        "--rate-limit",
        "2",
        "--rate-window-ms",
        "1000",
        "--burst-capacity",
        "2",
    ]
    yield from _launch_server(host, port, directory, limit_args, log_file=log_file)


READER_KEY = "reader-key"
WRITER_KEY = "writer-key"
JWT_SECRET = "integration-secret"


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture(name="authed_server_process")
def _authed_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server in api-key mode with a reader and a writer identity."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-authed")
    log_file = directory / "server.log"
    auth_args = [
        "--auth-mode",
        "api-key",
        "--auth-credentials",
        f"reader:{_sha256_hex(READER_KEY)}, writer:{_sha256_hex(WRITER_KEY)}",
        "--auth-roles",
        "reader:files:read, writer:files:read|files:write",
    ]
    yield from _launch_server(host, port, directory, auth_args, log_file=log_file)


BASIC_USER = "alice"
BASIC_PASSWORD = "s3cret-pass"


@pytest.fixture(name="basic_auth_server_process")
def _basic_auth_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server in HTTP Basic auth mode with a read-only identity."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-basic")
    log_file = directory / "server.log"
    auth_args = [
        "--auth-mode",
        "basic",
        "--auth-credentials",
        f"{BASIC_USER}:{_sha256_hex(BASIC_PASSWORD)}",
        "--auth-roles",
        f"{BASIC_USER}:files:read",
    ]
    yield from _launch_server(host, port, directory, auth_args, log_file=log_file)


@pytest.fixture(name="jwt_server_process")
def _jwt_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server in JWT mode with a shared HS256 secret."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-jwt")
    log_file = directory / "server.log"
    auth_args = ["--auth-mode", "jwt", "--jwt-secret", JWT_SECRET]
    yield from _launch_server(host, port, directory, auth_args, log_file=log_file)


@pytest.fixture(name="json_error_server_process")
def _json_error_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server with JSON-formatted error bodies enabled."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-json-errors")
    log_file = directory / "server.log"
    yield from _launch_server(
        host, port, directory, ["--error-format", "json"], log_file=log_file
    )


@pytest.fixture(name="websocket_server_process")
def _websocket_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server with the WebSocket echo endpoint enabled."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-ws")
    log_file = directory / "server.log"
    yield from _launch_server(
        host, port, directory, ["--enable-websocket"], log_file=log_file
    )


@pytest.fixture(name="sse_server_process")
def _sse_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server with the Server-Sent Events endpoint enabled."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-sse")
    log_file = directory / "server.log"
    yield from _launch_server(
        host, port, directory, ["--enable-sse"], log_file=log_file
    )


@pytest.fixture(name="session_server_process")
def _session_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server with signed session cookies enabled."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-session")
    log_file = directory / "server.log"
    yield from _launch_server(
        host,
        port,
        directory,
        ["--session-secret", "integration-session-secret"],
        log_file=log_file,
    )


@pytest.fixture(name="chunked_server_process")
def _chunked_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server with chunked request decoding and 100-continue enabled."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-chunked")
    log_file = directory / "server.log"
    yield from _launch_server(
        host,
        port,
        directory,
        ["--allow-chunked-requests", "--expect-continue"],
        log_file=log_file,
    )


@pytest.fixture()
def file_storage(tmp_path: Path) -> Path:
    """Provide a temporary directory for file persistence tests."""

    return tmp_path


@pytest.fixture()
def base_url(server_process: ServerProcessInfo) -> str:
    """Expose the running server base URL to integration tests."""

    return server_process["base_url"]

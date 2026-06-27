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


READER_KEY = "reader-key"
WRITER_KEY = "writer-key"
JWT_SECRET = "integration-secret"
BASIC_USER = "alice"
BASIC_PASSWORD = "s3cret-pass"


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _spawn_server(
    tmp_path_factory: "TempPathFactory",
    label: str,
    extra_args: list[str] | None = None,
) -> Generator[ServerProcessInfo, None, None]:
    """Reserve a port and launch a server in a temp directory under ``label``."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp(label)
    log_file = directory / "server.log"
    yield from _launch_server(host, port, directory, extra_args, log_file=log_file)


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Expose the repository root path to tests."""

    return PROJECT_ROOT


@pytest.fixture(name="server_process")
def _server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the HTTP server in a background process for integration tests."""

    yield from _spawn_server(tmp_path_factory, "server-files")


@pytest.fixture(name="limited_server_process")
def _limited_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the HTTP server with strict connection and rate limits for tests."""

    yield from _spawn_server(
        tmp_path_factory,
        "server-files-limited",
        [
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
        ],
    )


@pytest.fixture(name="authed_server_process")
def _authed_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server in api-key mode with a reader and a writer identity."""

    yield from _spawn_server(
        tmp_path_factory,
        "server-files-authed",
        [
            "--auth-mode",
            "api-key",
            "--auth-credentials",
            f"reader:{_sha256_hex(READER_KEY)}, writer:{_sha256_hex(WRITER_KEY)}",
            "--auth-roles",
            "reader:files:read, writer:files:read|files:write",
        ],
    )


@pytest.fixture(name="basic_auth_server_process")
def _basic_auth_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server in HTTP Basic auth mode with a read-only identity."""

    yield from _spawn_server(
        tmp_path_factory,
        "server-files-basic",
        [
            "--auth-mode",
            "basic",
            "--auth-credentials",
            f"{BASIC_USER}:{_sha256_hex(BASIC_PASSWORD)}",
            "--auth-roles",
            f"{BASIC_USER}:files:read",
        ],
    )


@pytest.fixture(name="jwt_server_process")
def _jwt_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server in JWT mode with a shared HS256 secret."""

    yield from _spawn_server(
        tmp_path_factory,
        "server-files-jwt",
        ["--auth-mode", "jwt", "--jwt-secret", JWT_SECRET],
    )


@pytest.fixture(name="json_error_server_process")
def _json_error_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server with JSON-formatted error bodies enabled."""

    yield from _spawn_server(
        tmp_path_factory, "server-files-json-errors", ["--error-format", "json"]
    )


@pytest.fixture(name="vhost_server")
def _vhost_server(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch a server with two virtual hosts serving distinct directories."""

    host = "127.0.0.1"
    port = reserve_port(host)
    default_dir = tmp_path_factory.mktemp("vhost-default")
    dir_a = tmp_path_factory.mktemp("vhost-a")
    dir_b = tmp_path_factory.mktemp("vhost-b")
    (dir_a / "hello.txt").write_text("from-a")
    (dir_b / "hello.txt").write_text("from-b")
    args = ["--vhost", f"a.test={dir_a}", "--vhost", f"b.test={dir_b}"]
    generator = _launch_server(
        host, port, default_dir, args, log_file=default_dir / "server.log"
    )
    info = next(generator)
    try:
        yield info
    finally:
        try:
            next(generator)
        except StopIteration:
            pass


@pytest.fixture(name="proxy_pair")
def _proxy_pair(
    tmp_path_factory: "TempPathFactory",
) -> Generator[dict, None, None]:
    """Launch an upstream server and a reverse proxy pointing /up/ at it."""

    host = "127.0.0.1"
    upstream_port = reserve_port(host)
    upstream_dir = tmp_path_factory.mktemp("proxy-upstream")
    upstream_gen = _launch_server(
        host, upstream_port, upstream_dir, log_file=upstream_dir / "upstream.log"
    )
    upstream = next(upstream_gen)

    proxy_port = reserve_port(host)
    proxy_dir = tmp_path_factory.mktemp("proxy-front")
    proxy_args = [
        "--proxy-pass",
        f"/up/=http://{host}:{upstream_port}",
        "--proxy-allow-host",
        host,
    ]
    proxy_gen = _launch_server(
        host, proxy_port, proxy_dir, proxy_args, log_file=proxy_dir / "proxy.log"
    )
    proxy = next(proxy_gen)
    try:
        yield {"proxy": proxy, "upstream": upstream}
    finally:
        for generator in (proxy_gen, upstream_gen):
            try:
                next(generator)
            except StopIteration:
                pass


@pytest.fixture(name="websocket_server_process")
def _websocket_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server with the WebSocket echo endpoint enabled."""

    yield from _spawn_server(
        tmp_path_factory, "server-files-ws", ["--enable-websocket"]
    )


@pytest.fixture(name="sse_server_process")
def _sse_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server with the Server-Sent Events endpoint enabled."""

    yield from _spawn_server(tmp_path_factory, "server-files-sse", ["--enable-sse"])


@pytest.fixture(name="session_server_process")
def _session_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server with signed session cookies enabled."""

    yield from _spawn_server(
        tmp_path_factory,
        "server-files-session",
        ["--session-secret", "integration-session-secret"],
    )


@pytest.fixture(name="chunked_server_process")
def _chunked_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the server with chunked request decoding and 100-continue enabled."""

    yield from _spawn_server(
        tmp_path_factory,
        "server-files-chunked",
        ["--allow-chunked-requests", "--expect-continue"],
    )


@pytest.fixture()
def file_storage(tmp_path: Path) -> Path:
    """Provide a temporary directory for file persistence tests."""

    return tmp_path


@pytest.fixture()
def base_url(server_process: ServerProcessInfo) -> str:
    """Expose the running server base URL to integration tests."""

    return server_process["base_url"]

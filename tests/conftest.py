"""Shared pytest fixtures for integration and unit tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Generator, TypedDict

import pytest

from tests.utils.http import reserve_port, wait_for_port

if TYPE_CHECKING:
    from _pytest.tmpdir import TempPathFactory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_ENTRYPOINT = PROJECT_ROOT / "main.py"


def _launch_server(
    host: str,
    port: int,
    directory: Path,
    extra_args: list[str] | None = None,
) -> Generator[ServerProcessInfo, None, None]:
    args = [
        sys.executable,
        str(SERVER_ENTRYPOINT),
        "--directory",
        str(directory),
        "--host",
        host,
        "--port",
        str(port),
    ]
    if extra_args:
        args.extend(extra_args)

    with subprocess.Popen(
        args,
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) as process:
        try:
            wait_for_port(host, port)
        except Exception:
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
    yield from _launch_server(host, port, directory)


@pytest.fixture(name="limited_server_process")
def _limited_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator[ServerProcessInfo, None, None]:
    """Launch the HTTP server with strict connection and rate limits for tests."""

    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-limited")
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
    yield from _launch_server(host, port, directory, limit_args)


@pytest.fixture()
def file_storage(tmp_path: Path) -> Path:
    """Provide a temporary directory for file persistence tests."""

    return tmp_path


@pytest.fixture()
def base_url(server_process: ServerProcessInfo) -> str:
    """Expose the running server base URL to integration tests."""

    return server_process["base_url"]

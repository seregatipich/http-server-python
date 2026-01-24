from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Dict, Generator

import pytest

from tests.utils.http import reserve_port, wait_for_port

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_ENTRYPOINT = PROJECT_ROOT / "main.py"


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture()
def server_process(tmp_path_factory) -> Generator[Dict[str, object], None, None]:
    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files")
    process = subprocess.Popen(
        [
            sys.executable,
            str(SERVER_ENTRYPOINT),
            "--directory",
            str(directory),
            "--host",
            host,
            "--port",
            str(port),
        ],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
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


@pytest.fixture()
def file_storage(tmp_path):
    return tmp_path


@pytest.fixture()
def base_url(server_process):
    return server_process["base_url"]

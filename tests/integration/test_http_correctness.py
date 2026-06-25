"""Integration tests for HTTP correctness features (Phase 3)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Generator

import pytest
import requests

from tests.conftest import _launch_server  # type: ignore[attr-defined]
from tests.utils.http import reserve_port

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from _pytest.tmpdir import TempPathFactory

    from tests.conftest import ServerProcessInfo


@pytest.fixture(name="gzip_server_process")
def _gzip_server_process(
    tmp_path_factory: "TempPathFactory",
) -> Generator["ServerProcessInfo", None, None]:
    host = "127.0.0.1"
    port = reserve_port(host)
    directory = tmp_path_factory.mktemp("server-files-gzip")
    log_file = directory / "server.log"
    yield from _launch_server(
        host,
        port,
        directory,
        ["--file-gzip", "--file-gzip-min-bytes", "8"],
        log_file=log_file,
    )


def _write(server: "ServerProcessInfo", name: str, data: bytes) -> None:
    (Path(server["directory"]) / name).write_bytes(data)


def test_head_mirrors_get_headers_without_body(
    server_process: "ServerProcessInfo",
) -> None:
    """HEAD returns GET headers (incl. Content-Length) with no body."""
    _write(server_process, "h.txt", b"abcdef")
    base_url = server_process["base_url"]
    response = requests.head(f"{base_url}/files/h.txt", timeout=5)
    assert response.status_code == 200
    assert response.headers["Content-Length"] == "6"
    assert response.headers["Accept-Ranges"] == "bytes"
    assert response.content == b""


def test_conditional_get_returns_304(server_process: "ServerProcessInfo") -> None:
    """A matching If-None-Match yields 304 with no body."""
    _write(server_process, "c.txt", b"conditional-body")
    base_url = server_process["base_url"]
    first = requests.get(f"{base_url}/files/c.txt", timeout=5)
    etag = first.headers["ETag"]
    second = requests.get(
        f"{base_url}/files/c.txt", headers={"If-None-Match": etag}, timeout=5
    )
    assert second.status_code == 304
    assert second.content == b""


def test_range_request_returns_206(server_process: "ServerProcessInfo") -> None:
    """A satisfiable Range yields 206 with the correct slice and Content-Range."""
    _write(server_process, "r.txt", b"0123456789")
    base_url = server_process["base_url"]
    response = requests.get(
        f"{base_url}/files/r.txt", headers={"Range": "bytes=2-5"}, timeout=5
    )
    assert response.status_code == 206
    assert response.content == b"2345"
    assert response.headers["Content-Range"] == "bytes 2-5/10"


def test_unsatisfiable_range_returns_416(
    server_process: "ServerProcessInfo",
) -> None:
    """An out-of-bounds Range yields 416 advertising the valid extent."""
    _write(server_process, "u.txt", b"0123456789")
    base_url = server_process["base_url"]
    response = requests.get(
        f"{base_url}/files/u.txt", headers={"Range": "bytes=50-60"}, timeout=5
    )
    assert response.status_code == 416
    assert response.headers["Content-Range"] == "bytes */10"


def test_put_creates_then_overwrites(server_process: "ServerProcessInfo") -> None:
    """PUT creates a new file (201) then overwrites it (204)."""
    base_url = server_process["base_url"]
    created = requests.put(f"{base_url}/files/p.txt", data=b"one", timeout=5)
    assert created.status_code == 201
    overwritten = requests.put(f"{base_url}/files/p.txt", data=b"two", timeout=5)
    assert overwritten.status_code == 204
    assert (Path(server_process["directory"]) / "p.txt").read_bytes() == b"two"


def test_delete_removes_file(server_process: "ServerProcessInfo") -> None:
    """DELETE removes an existing file (204) then 404s on repeat."""
    _write(server_process, "d.txt", b"bye")
    base_url = server_process["base_url"]
    assert requests.delete(f"{base_url}/files/d.txt", timeout=5).status_code == 204
    assert requests.delete(f"{base_url}/files/d.txt", timeout=5).status_code == 404


def test_gzip_compresses_eligible_files(
    gzip_server_process: "ServerProcessInfo",
) -> None:
    """With gzip enabled, eligible text files are returned gzip-encoded."""
    _write(gzip_server_process, "big.txt", b"x" * 500)
    base_url = gzip_server_process["base_url"]
    response = requests.get(
        f"{base_url}/files/big.txt",
        headers={"Accept-Encoding": "gzip"},
        timeout=5,
    )
    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") == "gzip"
    assert response.content == b"x" * 500

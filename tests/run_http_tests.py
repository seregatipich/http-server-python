"""(Тоже не говно код) script to exercise the HTTP server via smoke, load, and stress tests."""

import argparse
import concurrent.futures
import gzip
import os
import secrets
import socket
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

DEFAULT_BASE_URL = "http://localhost:4221"
TEST_TEMP_DIR = ".http-test-artifacts"


def ensure_temp_storage():
    """Create the temp artifact directory if needed and return its path."""
    os.makedirs(TEST_TEMP_DIR, exist_ok=True)
    return TEST_TEMP_DIR


def http_request(path, *, method="GET", data=None, headers=None, base_url=None):
    """Send an HTTP request and return status, body, and headers."""
    target = f"{base_url or DEFAULT_BASE_URL}{path}"
    payload = data.encode() if isinstance(data, str) else data
    request = urllib.request.Request(target, data=payload, method=method)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, response.read(), dict(response.headers)


def run_smoke_tests(base_url):
    """Validate echo, gzip, user-agent, and file routes."""
    print("Running smoke tests...")
    status, body, _ = http_request("/", base_url=base_url)
    if status != 200 or body:
        raise RuntimeError("Root endpoint failed")

    status, body, _ = http_request("/echo/hello", base_url=base_url)
    if status != 200 or body != b"hello":
        raise RuntimeError("Echo endpoint failed")

    status, body, _ = http_request("/user-agent", base_url=base_url)
    if status != 200 or not body:
        raise RuntimeError("User-Agent endpoint failed")

    status, body, headers = http_request(
        "/echo/gzip",
        base_url=base_url,
        headers={"Accept-Encoding": "gzip"},
    )
    if status != 200 or headers.get("Content-Encoding") != "gzip":
        raise RuntimeError("Gzip negotiation failed")
    if gzip.decompress(body) != b"gzip":
        raise RuntimeError("Gzip body mismatch")

    ensure_temp_storage()
    filename = f"test-{int(time.time() * 1000)}-{secrets.token_hex(4)}.txt"
    temp_path = f"{TEST_TEMP_DIR}/{filename}"
    payload = "persistent-body"
    status, _, _ = http_request(
        f"/files/{temp_path}",
        method="POST",
        data=payload,
        base_url=base_url,
    )
    if status != 201:
        raise RuntimeError("File upload failed")
    status, body, _ = http_request(f"/files/{temp_path}", base_url=base_url)
    if status != 200 or body.decode() != payload:
        raise RuntimeError("File download mismatch")

    stored_file = os.path.join(TEST_TEMP_DIR, filename)
    if os.path.exists(stored_file):
        os.remove(stored_file)

    print("Smoke tests passed")


def run_persistent_connection_test(base_url):
    """Verify that multiple requests can be sent over the same socket."""
    print("Running persistent connection test...")
    parsed = urlparse(base_url or DEFAULT_BASE_URL)
    host, port = parsed.hostname, parsed.port

    with socket.create_connection((host, port)) as sock:
        # Request 1
        sock.sendall(b"GET /echo/first HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response1 = sock.recv(4096)
        if b"HTTP/1.1 200 OK" not in response1 or b"first" not in response1:
            raise RuntimeError(f"Persistent connection failed on first request: {response1[:50]}")

        # Request 2
        sock.sendall(b"GET /echo/second HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response2 = sock.recv(4096)
        if b"HTTP/1.1 200 OK" not in response2 or b"second" not in response2:
            raise RuntimeError(f"Persistent connection failed on second request: {response2[:50]}")

    print("Persistent connection test passed")


def run_large_body_test(base_url):
    """Verify handling of large file uploads and downloads."""
    print("Running large body test...")
    ensure_temp_storage()
    filename = f"large-test-{int(time.time())}.bin"
    temp_path = f"{TEST_TEMP_DIR}/{filename}"
    size = 5 * 1024 * 1024  # 5MB
    payload = secrets.token_bytes(size)

    # POST large file
    status, _, _ = http_request(
        f"/files/{temp_path}",
        method="POST",
        data=payload,
        base_url=base_url,
    )
    if status != 201:
        raise RuntimeError(f"Large file upload failed with status {status}")

    # GET large file
    status, body, _ = http_request(f"/files/{temp_path}", base_url=base_url)
    if status != 200 or body != payload:
        raise RuntimeError(f"Large file download mismatch (size: {len(body)})")

    # Cleanup
    stored_file = os.path.join(TEST_TEMP_DIR, filename)
    if os.path.exists(stored_file):
        os.remove(stored_file)

    print("Large body test passed")


def run_parallel_requests(total, workers, path, base_url):
    """Execute identical requests concurrently and collect stats."""
    start = time.perf_counter()

    def fetch(_):
        try:
            status, _, _ = http_request(path, base_url=base_url)
            return status == 200
        except urllib.error.URLError:
            return False
        except ConnectionError:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        successes = sum(pool.map(fetch, range(total)))

    duration = time.perf_counter() - start
    errors = total - successes
    rps = total / duration if duration else float("inf")
    return duration, errors, rps


def run_load_tests(base_url):
    """Measure performance across low to very-high scenarios."""
    scenarios = [
        ("low", 20, 1),
        ("medium", 200, 5),
        ("high", 500, 20),
        ("very-high", 1000, 40),
    ]
    print("Running load tests...")
    for label, total, workers in scenarios:
        duration, errors, rps = run_parallel_requests(
            total,
            workers,
            "/echo/load",
            base_url,
        )
        print(
            f"{label:>10}: total={total:5d} workers={workers:3d} "
            f"duration={duration:.3f}s rps={rps:.1f} errors={errors}"
        )
        if errors:
            raise RuntimeError(f"Load scenario '{label}' encountered {errors} errors")
    print("Load tests passed")


def run_stress_tests(base_url):
    """Apply higher volumes and concurrency to find failure thresholds."""
    levels = [
        ("2k", 2000, 50),
        ("5k", 5000, 100),
        ("10k", 10000, 200),
        ("20k", 20000, 400),
    ]
    print("Running stress tests...")
    for label, total, workers in levels:
        duration, errors, rps = run_parallel_requests(
            total,
            workers,
            "/echo/failure-test",
            base_url,
        )
        print(
            f"{label:>4}: total={total:5d} workers={workers:3d} "
            f"duration={duration:.2f}s rps={rps:.1f} errors={errors}"
        )
        if errors:
            raise RuntimeError(f"Stress scenario '{label}' encountered {errors} errors")
    print("Stress tests passed")


def main():
    """Parse CLI arguments and run the requested test suites."""
    parser = argparse.ArgumentParser(description="Exercise the HTTP server endpoints.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--skip-smoke", action="store_true")
    parser.add_argument("--skip-load", action="store_true")
    parser.add_argument("--skip-stress", action="store_true")
    args = parser.parse_args()

    if not args.skip_smoke:
        run_smoke_tests(args.base_url)

    run_persistent_connection_test(args.base_url)
    run_large_body_test(args.base_url)

    if not args.skip_load:
        run_load_tests(args.base_url)
    if not args.skip_stress:
        run_stress_tests(args.base_url)


if __name__ == "__main__":
    main()

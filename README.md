# HTTP Server

![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

Threaded HTTP/1.1 server with echo, user-agent inspection, configurable file IO, gzip negotiation, and optional TLS termination. Ideal for experimenting with raw socket handling while keeping the codebase dependency-light.

## Features

- **Concurrency and persistence**: Every connection is handled in a dedicated `threading.Thread`, and sockets remain open for multiple requests unless the client asks to close.
- **Purpose-built routing**: `/`, `/echo/<message>`, `/user-agent`, and `/files/<path>` cover the core exercise flows without an external framework.
- **Gzip negotiation**: Payloads automatically compress when `Accept-Encoding: gzip` advertises a non-zero quality factor.
- **File uploads and downloads**: `POST /files/<path>` writes raw bytes to the configured directory and `GET /files/<path>` streams content via `Transfer-Encoding: chunked` for large artifacts.
- **Transport security**: Passing `--cert` and `--key` enables TLS 1.3 termination directly in the server process.
- **Security headers**: Strict-Transport-Security, Content-Security-Policy, and X-Content-Type-Options are attached to every response, including 404s.
- **Request validation and sandboxing**: `/files/*` is restricted to the configured root, blocking traversal (`..`) and null bytes; uploads enforce `Content-Length` and reject bodies over `HTTP_SERVER_MAX_BODY_BYTES` (default 5 MiB).
- **Structured logging**: `logging_config.configure_logging()` wires a shared logger hierarchy (`http_server.*`) with configurable destinations and levels.
- **Connection and rate limiting**: configurable caps for total sockets, per-IP concurrency, and token-bucket request throttling with standards-based RateLimit headers.

## Requirements

- Python 3.12+

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

After completing these steps, continue with the detailed [Usage Guide](docs/USAGE_GUIDE.md) for TLS setup, LAN access, and operational workflows.

## Usage

```bash
python3 main.py [--directory <path>] [--host <host>] [--port <port>] \
  [--cert <cert.pem>] [--key <key.pem>] \
  [--log-level <LEVEL>] [--log-destination <stdout|path>] \
  [--max-connections <int>] [--max-connections-per-ip <int>] \
  [--rate-limit <int>] [--rate-window-ms <int>] [--burst-capacity <int>] \
  [--rate-limit-dry-run]
```

- `--directory`: root for `/files/*` operations (defaults to the current working directory).
- `--host`: bind host (default `localhost`).
- `--port`: bind port (default `4221`).
- `--cert`/`--key`: PEM files required to serve HTTPS.
- `--log-level`: DEBUG, INFO, WARNING, ERROR, or CRITICAL (default `INFO`).
- `--log-destination`: `stdout` or a filesystem path. File destinations rotate at 10 MB with five retained backups.
- `HTTP_SERVER_MAX_BODY_BYTES`: optional override for maximum accepted request body size in bytes (defaults to 5 MiB).
- `--max-connections` / `HTTP_SERVER_MAX_CONNECTIONS`: global concurrent socket limit (0 disables the cap).
- `--max-connections-per-ip` / `HTTP_SERVER_MAX_CONNECTIONS_PER_IP`: per-client socket cap (0 disables the cap).
- `--rate-limit` / `HTTP_SERVER_RATE_LIMIT`: requests allowed per window (0 disables enforcement).
- `--rate-window-ms` / `HTTP_SERVER_RATE_WINDOW_MS`: window size for the token bucket in milliseconds.
- `--burst-capacity` / `HTTP_SERVER_BURST_CAPACITY`: bucket capacity to allow short bursts.
- `--rate-limit-dry-run` / `HTTP_SERVER_RATE_LIMIT_DRY_RUN`: log 429 conditions without blocking traffic.

Environment variables mirror the logging flags:

- `HTTP_SERVER_LOG_LEVEL`
- `HTTP_SERVER_LOG_DESTINATION`

## Request lifecycle

1. **Startup and connection control**
   - `main()` parses CLI flags, configures logging, creates the listening socket, and optionally wraps it in TLS.
   - `ConnectionLimiter` enforces global/per-IP socket caps before any worker thread is spawned.
   - Each accepted client runs inside its own daemon `threading.Thread`, enabling keep-alive sessions.
2. **Request read and validation**
   - `_read_request_with_validation()` reads bytes with a bounded buffer, enforces `HTTP_SERVER_MAX_BODY_BYTES`, and surfaces structured parser errors.
   - `validate_request()` whitelists HTTP methods, checks required headers, blocks traversal/null-bytes, and ensures `/files/*` paths stay under the configured root.
3. **Rate limiting**
   - `TokenBucketLimiter.consume()` enforces the configured window, returns `RateLimitDecision`, and injects draft `RateLimit-*` headers whether the request is allowed or logged in dry-run.
4. **Routing and endpoint behavior**
   - `build_response()` defaults to `404` before dispatching to `/`, `/echo/<msg>`, `/user-agent`, and `/files/<path>`.
   - `/echo/` and `/user-agent` reuse `text_response()`, which negotiates gzip transparently.
5. **File sandbox operations**
   - `resolve_sandbox_path()` resolves all `/files/*` requests inside the configured directory, rejecting requests that would escape via symlinks or `..`.
   - GET streams files via chunked transfer encoding; POST ensures parent directories exist and writes the exact request body.
6. **Response serialization**
   - `send_response()` merges security headers, applies chunked framing when a generator is present, and streams chunks until the handler signals completion.
   - Responses honor `Connection: close` directives and release rate/connection counters as worker threads unwind.

## Endpoints

| Method | Path pattern    | Description                               |
|--------|-----------------|-------------------------------------------|
| GET    | `/`             | Returns 200 OK for health checks          |
| GET    | `/echo/<msg>`   | Responds with `<msg>` as `text/plain`     |
| GET    | `/user-agent`   | Surfaces the incoming `User-Agent` header |
| GET    | `/files/<path>` | Streams a file from the configured root   |
| POST   | `/files/<path>` | Writes the request body to disk           |

Responses advertise `Content-Encoding: gzip` when the client opts in.

## Logging

`logging_config.configure_logging()` sets the base logger once, giving the server and compression modules consistent formatting and context. Use `--log-level DEBUG` when you need socket-level traces and revert back to INFO to keep noise low. Point `--log-destination` to a file when long-running tests would overwhelm stdout.

## Testing

### Pytest

```bash
source venv/bin/activate
python -m pytest            # run entire suite
python -m pytest -m integration  # run only integration tests
```

Unit tests cover parsing, compression, and CLI behavior. Integration tests spawn the server process (including HTTPS mode) to verify routing, headers, persistent sockets, and chunked transfers.

### Manual runner

```bash
python3 tests/manual_http_runner.py [--base-url <url>] [--skip-smoke] [--skip-load] [--skip-stress]
```

The manual CLI drives smoke checks, persistent-connection probes, multi-megabyte file transfers, and progressive load/stress tiers. Run results are stored in `.http-test-artifacts/`, which stays out of version control.

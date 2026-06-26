# HTTP Server

![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

Threaded HTTP/1.1 server with echo, user-agent inspection, configurable file IO, gzip negotiation, and optional TLS termination. Ideal for experimenting with raw socket handling while keeping the codebase dependency-light.

## Features

- **Concurrency and persistence**: Every connection is handled in a dedicated `threading.Thread`, and sockets remain open for multiple requests unless the client asks to close.
- **Purpose-built routing**: `/`, `/echo/<message>`, `/user-agent`, `/healthz`, and `/files/<path>` cover the core exercise flows without an external framework.
- **Graceful shutdown**: SIGTERM/SIGINT trigger a draining phase where new connections receive 503 responses while in-flight requests complete within a configurable grace period.
- **Health check endpoint**: `GET /healthz` returns 200 OK during normal operation and 503 Service Unavailable when draining, enabling zero-downtime deployments.
- **Gzip negotiation**: Payloads automatically compress when `Accept-Encoding: gzip` advertises a non-zero quality factor.
- **File uploads and downloads**: `POST /files/<path>` writes raw bytes to the configured directory and `GET /files/<path>` streams content via `Transfer-Encoding: chunked` for large artifacts.
- **Authentication and authorization**: opt-in api-key or hand-rolled HS256 JWT auth (zero dependencies) with scope-based access control on `/files/*`.
- **Transport security**: Passing `--cert` and `--key` enables TLS 1.3 termination directly in the server process.
- **Security headers**: Strict-Transport-Security, Content-Security-Policy, and X-Content-Type-Options are attached to every response, including 404s.
- **Request validation and sandboxing**: `/files/*` is restricted to the configured root, blocking traversal (`..`) and null bytes; uploads enforce `Content-Length` and reject bodies over `HTTP_SERVER_MAX_BODY_BYTES` (default 5 MiB).
- **Structured logging**: `pyhttpd.adapters.logging.setup.configure_logging()` wires a shared logger hierarchy (`http_server.*`) with configurable destinations and levels.
- **Connection and rate limiting**: configurable caps for total sockets, per-IP concurrency, and token-bucket request throttling with standards-based RateLimit headers.

## Requirements

- Python 3.12+

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e '.[dev]'
```

After completing these steps, continue with the detailed [Usage Guide](docs/USAGE_GUIDE.md) for TLS setup, LAN access, and operational workflows.

## Usage

```bash
pyhttpd [--directory <path>] [--host <host>] [--port <port>] \
  [--cert <cert.pem>] [--key <key.pem>] \
  [--log-level <LEVEL>] [--log-destination <stdout|path>] \
  [--max-connections <int>] [--max-connections-per-ip <int>] \
  [--rate-limit <int>] [--rate-window-ms <int>] [--burst-capacity <int>] \
  [--rate-limit-dry-run] \
  [--socket-timeout <seconds>] [--shutdown-grace-seconds <seconds>] \
  [--auth-mode <none|api-key|jwt>] [--auth-credentials <list>] [--auth-roles <list>] \
  [--jwt-secret <secret>] [--jwt-issuer <iss>] [--jwt-audience <aud>]
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
- `--socket-timeout` / `HTTP_SERVER_SOCKET_TIMEOUT`: socket timeout in seconds for request processing (default 60).
- `--shutdown-grace-seconds` / `HTTP_SERVER_SHUTDOWN_GRACE_SECONDS`: grace period in seconds for graceful shutdown (default 30).

- `--auth-mode` / `HTTP_SERVER_AUTH_MODE`: `none` (default), `api-key`, or `jwt`.
- `--auth-credentials` / `HTTP_SERVER_AUTH_CREDENTIALS`: comma-separated `identity:sha256hex` api-key pairs (store the SHA-256 hex of each key, never the raw key).
- `--auth-roles` / `HTTP_SERVER_AUTH_ROLES`: comma-separated `identity:scope|scope` role assignments.
- `--jwt-secret` / `HTTP_SERVER_JWT_SECRET`: shared secret for HS256 verification.
- `--jwt-issuer` / `HTTP_SERVER_JWT_ISSUER`: expected `iss` claim (optional).
- `--jwt-audience` / `HTTP_SERVER_JWT_AUDIENCE`: expected `aud` claim (optional).

Environment variables mirror the logging flags:

- `HTTP_SERVER_LOG_LEVEL`
- `HTTP_SERVER_LOG_DESTINATION`

## Authentication

Authentication is opt-in (`--auth-mode none` by default). When enabled, an auth
middleware runs after request validation and enforces scope-based access:
`GET /files/*` requires `files:read` and `POST /files/*` requires `files:write`.
`/healthz` and CORS preflight requests are always public.

- **api-key** — clients send `Authorization: ApiKey <key>`. Keys are matched by
  constant-time comparison of their SHA-256 hash, so only hashes live in config.
- **jwt** — clients send `Authorization: Bearer <token>`. Tokens are verified as
  HS256 (hand-rolled on the standard library, zero dependencies): the algorithm
  is pinned to `HS256` (no `alg=none`), the signature is checked with
  `hmac.compare_digest`, and `exp`/`nbf`/`iss`/`aud` claims are validated. The
  `sub` claim becomes the identity and the space-delimited `scope` claim its
  scopes.

Missing or invalid credentials return `401` with a `WWW-Authenticate` challenge;
an authenticated principal lacking the required scope returns `403`. Credentials
and secrets are never logged — only the active auth mode is recorded at startup.

```bash
# api-key example: a read-only "reader" and a read/write "writer"
pyhttpd --auth-mode api-key \
  --auth-credentials "reader:$(printf reader-key | shasum -a 256 | cut -d' ' -f1)" \
  --auth-roles "reader:files:read"
```

## Request lifecycle

1. **Startup and connection control**
   - `main()` parses CLI flags, configures logging, creates the listening socket, and optionally wraps it in TLS.
   - `ConnectionLimiter` enforces global/per-IP socket caps before any worker thread is spawned.
   - Each accepted client runs inside its own daemon `threading.Thread`, enabling keep-alive sessions.
2. **Request read and validation**
   - `_read_request_with_validation()` reads bytes with a bounded buffer, enforces `HTTP_SERVER_MAX_BODY_BYTES`, and surfaces structured parser errors.
   - Request bodies are framed by `Content-Length` only; a `Transfer-Encoding` header or conflicting `Content-Length` values are rejected with `400` to foreclose request-smuggling desynchronization (RFC 9112 §6.3), and `Content-Length` must be canonical ASCII digits.
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

## Architecture

The codebase follows a clean-architecture layering under `src/pyhttpd/`, with dependencies pointing inward only:

- `domain/` — dependency-free core: HTTP value types, errors, config schemas, rate-limit decisions, sandbox rules, and port protocols.
- `application/` — request pipeline, routing, middleware (CORS, rate limiting, validation), response rendering, and endpoint handlers. Depends on `domain` only.
- `adapters/` — infrastructure that satisfies the domain ports: sockets and TLS, the threaded transport/worker loop, logging, token-bucket rate limiting, clock, ids, and config loading.
- `composition.py` — composition root that wires adapters, application, and domain into a runnable `Server`.
- `cli.py` / `__main__.py` — entrypoints that parse arguments and invoke the composition root.

## Endpoints

| Method | Path pattern    | Description                                          |
|--------|-----------------|------------------------------------------------------|
| GET    | `/`             | Returns 200 OK for health checks                     |
| GET    | `/healthz`      | Returns 200 OK when healthy, 503 when draining       |
| GET    | `/echo/<msg>`   | Responds with `<msg>` as `text/plain`                |
| GET    | `/user-agent`   | Surfaces the incoming `User-Agent` header            |
| GET    | `/files/<path>` | Streams a file from the configured root              |
| POST   | `/files/<path>` | Writes the request body to disk                      |

Responses advertise `Content-Encoding: gzip` when the client opts in.

## Logging

`pyhttpd.adapters.logging.setup.configure_logging()` sets the base logger once, giving the server and compression modules consistent formatting and context. Use `--log-level DEBUG` when you need socket-level traces and revert back to INFO to keep noise low. Point `--log-destination` to a file when long-running tests would overwhelm stdout.

For a complete list of logged events and their structured fields, see the [Logging Namespace Catalog](docs/logging/namespace_catalog.md).

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

### Performance

Throughput and latency baselines live in `tests/performance/` and are excluded
from the default run (the `performance` marker). Run them explicitly:

```bash
python -m pytest -m performance -s   # prints req/s and p50/p95 latency
```

## Observability

Pass `--metrics` (or `HTTP_SERVER_METRICS=true`) to expose `GET /metrics` in
Prometheus text exposition format (no client library, stdlib only):

```bash
pyhttpd --metrics
curl -s localhost:4221/metrics | grep -E '^http_requests_total|^http_request_duration_seconds_bucket'
```

Instruments: request counter (method/route/status), error counter, latency
histogram, in-flight gauge, and rejection counters (rate-limit / connection /
draining). `/metrics` is excluded from its own metrics. The endpoint is off by
default, so it never appears unless explicitly enabled.

## API documentation

The full endpoint surface — methods, status codes, conditional/range behavior,
auth schemes, and response headers — is described in an OpenAPI 3.1 spec rooted
at [`docs/openapi.yaml`](docs/openapi.yaml), which references the path items in
[`docs/openapi.paths.yaml`](docs/openapi.paths.yaml) and the reusable parameters,
headers, and responses in
[`docs/openapi.components.yaml`](docs/openapi.components.yaml). The split spec is
validated end-to-end in `tests/unit/test_openapi_spec.py`.

## Deployment

A multi-stage `Dockerfile` produces a slim image that runs as a non-root user
and carries zero Python runtime dependencies. The server binds `0.0.0.0` inside
the container and ships a stdlib-based `HEALTHCHECK` against `/healthz`.

```bash
docker build -t pyhttpd .
docker run --rm -p 8080:8080 -v "$PWD/data:/srv" pyhttpd
# or
docker compose up --build
curl -s localhost:8080/healthz
```

`docker-compose.yml` maps `8080:8080`, mounts `./data` to `/srv`, and restarts
unless stopped.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request across Python
3.11 and 3.12: `black --check`, `isort --check-only`, `ruff`, `mypy`, `pylint`,
the full `pytest` suite, and `pip-audit` against the (empty) runtime dependency
closure. A dependent job builds the container image on green.

## Housekeeping

```bash
make clean   # remove tool caches, build metadata, __pycache__, and stray logs
```

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
- **Structured logging**: `logging_config.configure_logging()` wires a shared logger hierarchy (`http_server.*`) with configurable destinations and levels.

## Requirements

- Python 3.12+

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py [--directory <path>] [--host <host>] [--port <port>] \
  [--cert <cert.pem>] [--key <key.pem>] \
  [--log-level <LEVEL>] [--log-destination <stdout|path>]
```

- `--directory`: root for `/files/*` operations (defaults to the current working directory).
- `--host`: bind host (default `localhost`).
- `--port`: bind port (default `4221`).
- `--cert`/`--key`: PEM files required to serve HTTPS.
- `--log-level`: DEBUG, INFO, WARNING, ERROR, or CRITICAL (default `INFO`).
- `--log-destination`: `stdout` or a filesystem path. File destinations rotate at 10 MB with five retained backups.

Environment variables mirror the logging flags:

- `HTTP_SERVER_LOG_LEVEL`
- `HTTP_SERVER_LOG_DESTINATION`

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

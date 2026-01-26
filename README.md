# HTTP Server

![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

Python HTTP server supporting echo, user-agent inspection, gzip, and basic file IO endpoints. Designed for local experimentation without external dependencies.

## Features

- **Persistent Connections**: Uses `threading.Thread` to handle concurrent clients and a `while True` loop to support multiple requests over a single connection.
- **Dynamic Routing**: Built-in handlers for echo, user-agent, and file operations.
- **Compression**: Automatic `gzip` compression when `Accept-Encoding: gzip` is present.
- **File Storage**: Configurable root directory for file uploads and downloads.
- **Chunked Streaming**: Large file downloads stream via `Transfer-Encoding: chunked` to avoid buffering entire payloads.

## Requirements

- Python 3.12+

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
```

## Usage

```bash
python3 main.py [--directory <path>] [--host <host>] [--port <port>] \
  [--log-level <LEVEL>] [--log-destination <stdout|path>]
```

- `--directory`: root for `/files/*` operations (defaults to current directory)
- `--host`: bind host (default `localhost`)
- `--port`: bind port (default `4221`)
- `--log-level`: DEBUG, INFO, WARNING, ERROR, or CRITICAL (default `INFO`)
- `--log-destination`: `stdout` or file path; when a file is provided, logs rotate at 10 MB with 5 backups.

Environment overrides mirror the CLI defaults:

- `HTTP_SERVER_LOG_LEVEL`
- `HTTP_SERVER_LOG_DESTINATION`

## Endpoints

| Method | Path pattern        | Description                                 |
|--------|---------------------|---------------------------------------------|
| GET    | `/`                 | Health check (200 OK)                       |
| GET    | `/echo/<msg>`       | Returns `<msg>` as `text/plain`             |
| GET    | `/user-agent`       | Returns the `User-Agent` request header      |
| GET    | `/files/<path>`     | Serves file from disk                       |
| POST   | `/files/<path>`     | Saves request body to disk                  |

Responses use `Content-Encoding: gzip` if supported by the client.

## Testing

### Pytest suite

The repository now ships a full unit, integration, and performance pytest suite.

```bash
source venv/bin/activate
python -m pytest          # run everything
python -m pytest -m integration   # run only integration tests
```

Key coverage areas include gzip negotiation, socket parsing, HTTP response building, connection reuse, and end-to-end endpoint checks.

### Manual operational runner

For smoke, load, and stress validations outside pytest, use the manual runner:

```bash
python3 tests/manual_http_runner.py [--base-url <url>] [--skip-smoke] [--skip-load] [--skip-stress]
```

This CLI exercises:

- **Smoke tests** for echo, user-agent, gzip, and `/files` flows.
- **Persistent connection** reuse on a raw socket.
- **Large body** uploads/downloads (5 MB).
- **Load tiers** spanning 20–1,000 requests with increasing concurrency.
- **Stress tiers** up to 20,000 requests and 400 workers.

Test artifacts land in `.http-test-artifacts/`, which is git-ignored.

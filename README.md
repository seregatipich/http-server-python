# (НЕ ГОВНОКОД) HTTP Server

Python HTTP server supporting echo, user-agent inspection, gzip, and basic file IO endpoints. Designed for local experimentation without external dependencies.

## Features

- **Persistent Connections**: Uses `threading.Thread` to handle concurrent clients and a `while True` loop to support multiple requests over a single connection.
- **Dynamic Routing**: Built-in handlers for echo, user-agent, and file operations.
- **Compression**: Automatic `gzip` compression when `Accept-Encoding: gzip` is present.
- **File Storage**: Configurable root directory for file uploads and downloads.

## Requirements

- Python 3.12+

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Usage

```bash
python3 main.py [--directory <path>]
```

The `--directory` flag sets the root for `/files/*` operations (defaults to current directory).

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

The project includes a comprehensive test suite in `tests/run_http_tests.py` (тоже не говно код).

### Test Scenarios

- **Smoke Tests**: Basic validation of all core endpoints.
- **Persistent Connections**: Verifies multiple requests over a single TCP socket.
- **Large Body Test**: Handles 5MB binary payloads to ensure stability.
- **Load & Stress Tests**:
    - **Low to Very High**: 20 to 1,000 requests with increasing concurrency.
    - **Stress Tiers**: Up to 20,000 requests with 400 concurrent workers.

### Running Tests

1. Start the server:
   ```bash
   python3 main.py --directory .
   ```

2. Run the automated suite:
   ```bash
   python3 tests/run_http_tests.py
   ```

   **Options:**
   - `--skip-smoke`, `--skip-load`, `--skip-stress`: Skip specific tiers.
   - `--base-url <url>`: Target a different server instance.

Test artifacts are stored in `.http-test-artifacts/` (ignored by git).

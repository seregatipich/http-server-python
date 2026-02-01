# Usage Guide

Comprehensive instructions for developing, operating, and exercising the HTTP server on a local network.

## 1. Prerequisites

- **Python**: 3.12 or newer (`python3 --version`).
- **OpenSSL**: Required for generating self-signed certificates (`openssl version`).
- **Pip**: Ships with Python 3.12; upgrade if necessary (`python3 -m pip install --upgrade pip`).
- **Local network access**: Ability to bind to `0.0.0.0` and accept inbound connections on the chosen port (default 4221).

## 2. Before you continue

Complete the setup instructions in `README.md` (virtual environment creation and dependency installation). Keep that virtual environment active while following the operational steps below.

## 3. Generate TLS certificates (optional but recommended)

The repository expects PEM files in `certs/`. Create the directory if it does not exist.

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes -subj "/C=US/ST=CA/L=San Francisco/O=Local Dev/OU=HTTP Server/CN=localhost"
```

- `certs/cert.pem`: public certificate served to clients.
- `certs/key.pem`: private key (keep it secret).
- Browsers and `curl` will warn about the self-signed certificate; use `curl -k` for testing.

## 4. Running the server

### 4.1 Basic HTTP

```bash
source venv/bin/activate
python3 main.py --directory ./data --host localhost --port 4221
```

- `--directory` selects the root for `/files/*` requests. Create the folder beforehand if it should be isolated from the repo root.
- `--host localhost` keeps the server reachable only from the same machine.

### 4.2 HTTPS with TLS termination

```bash
source venv/bin/activate
python3 main.py --directory ./data --host 0.0.0.0 --port 4221 \
  --cert certs/cert.pem --key certs/key.pem
```

- Binding to `0.0.0.0` makes the server accessible from any interface.
- The logger records whether TLS is enabled (`tls: true`).

### 4.3 Logging controls

- `--log-level` accepts `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` (default `INFO`).
- `--log-destination stdout` keeps logs in the terminal. Passing a filesystem path enables 10 MB rotating files with five backups.

Environment variables `HTTP_SERVER_LOG_LEVEL` and `HTTP_SERVER_LOG_DESTINATION` override the defaults before CLI parsing.

### 4.4 Request Limits

- `HTTP_SERVER_MAX_BODY_BYTES` controls the maximum allowed request body size (default 5 MiB).
- `--max-connections` / `HTTP_SERVER_MAX_CONNECTIONS` cap total concurrent sockets (0 disables the cap).
- `--max-connections-per-ip` / `HTTP_SERVER_MAX_CONNECTIONS_PER_IP` cap per-client sockets (0 disables the cap).
- `--rate-limit` / `HTTP_SERVER_RATE_LIMIT` set token bucket allowance per window (0 disables enforcement).
- `--rate-window-ms` / `HTTP_SERVER_RATE_WINDOW_MS` configure the refill window in milliseconds.
- `--burst-capacity` / `HTTP_SERVER_BURST_CAPACITY` set the bucket size to allow brief bursts.
- `--rate-limit-dry-run` / `HTTP_SERVER_RATE_LIMIT_DRY_RUN` log limit hits without blocking traffic.

### 4.5 CORS Configuration

The server supports Cross-Origin Resource Sharing (CORS) to enable browser-based clients from different origins to access the API. CORS is configured via CLI arguments or environment variables.

#### Default Behavior

By default, the server allows all origins (`*`) with the following configuration:
- **Allowed Origins**: `*` (all origins)
- **Allowed Methods**: `GET`, `POST`, `OPTIONS`
- **Allowed Headers**: `Content-Type`, `Authorization`
- **Exposed Headers**: `X-Request-ID`
- **Allow Credentials**: `false`
- **Max Age**: `86400` seconds (24 hours)

#### Configuration Options

| CLI Argument | Environment Variable | Default | Description |
|--------------|---------------------|---------|-------------|
| `--cors-allowed-origins` | `HTTP_SERVER_CORS_ALLOWED_ORIGINS` | `*` | Comma-separated list of allowed origins |
| `--cors-allowed-methods` | `HTTP_SERVER_CORS_ALLOWED_METHODS` | `GET,POST,OPTIONS` | Comma-separated list of allowed HTTP methods |
| `--cors-allowed-headers` | `HTTP_SERVER_CORS_ALLOWED_HEADERS` | `Content-Type,Authorization` | Comma-separated list of allowed request headers |
| `--cors-expose-headers` | `HTTP_SERVER_CORS_EXPOSE_HEADERS` | `X-Request-ID` | Comma-separated list of headers exposed to the client |
| `--cors-allow-credentials` | `HTTP_SERVER_CORS_ALLOW_CREDENTIALS` | `false` | Allow credentials (cookies, authorization headers) |
| `--cors-max-age` | `HTTP_SERVER_CORS_MAX_AGE` | `86400` | Preflight cache duration in seconds |

#### Examples

**Restrict to specific origins:**

```bash
python3 main.py --directory ./data \
  --cors-allowed-origins "https://app.example.com,https://admin.example.com"
```

**Enable credentials with specific origin:**

```bash
python3 main.py --directory ./data \
  --cors-allowed-origins "https://app.example.com" \
  --cors-allow-credentials
```

**Custom headers and methods:**

```bash
python3 main.py --directory ./data \
  --cors-allowed-methods "GET,POST,PUT,DELETE,OPTIONS" \
  --cors-allowed-headers "Content-Type,Authorization,X-Custom-Header"
```

#### Testing CORS

**Simple CORS request:**

```bash
curl -i -H "Origin: https://example.com" http://localhost:4221/echo/test
```

Expected headers in response:
- `Access-Control-Allow-Origin: *`
- `Access-Control-Expose-Headers: X-Request-ID`

**Preflight OPTIONS request:**

```bash
curl -i -X OPTIONS http://localhost:4221/files/data \
  -H "Origin: https://example.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"
```

Expected response:
- Status: `204 No Content`
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type, Authorization`
- `Access-Control-Max-Age: 86400`

**Browser fetch example:**

```javascript
// From a web page at https://example.com
fetch('http://localhost:4221/echo/hello', {
  method: 'GET',
  headers: {
    'Content-Type': 'application/json'
  }
})
.then(response => response.text())
.then(data => console.log(data));
```

#### Security Considerations

1. **Never use wildcard (`*`) with credentials**: When `--cors-allow-credentials` is enabled, always specify exact origins. The server automatically enforces this by echoing the specific origin instead of `*`.

2. **Restrict origins in production**: While `*` is convenient for development, production deployments should explicitly list trusted origins.

3. **Minimize exposed headers**: Only expose headers that clients genuinely need to read.

4. **Preflight caching**: The `--cors-max-age` setting controls how long browsers cache preflight responses. Longer values reduce preflight requests but delay configuration changes.

## 5. Discovering the host IP for LAN access

1. Determine the network interface IP on the server machine:
   - macOS/Linux: `ipconfig getifaddr en0` (Wi-Fi) or `ifconfig` / `ip addr`.
   - Windows (WSL): `ipconfig` in PowerShell or Command Prompt.
2. Ensure the firewall allows inbound TCP traffic on the chosen port.
3. Start the server binding to that IP or to `0.0.0.0`.
4. Note the full base URL, e.g., `https://192.168.1.50:4221`.

## 6. Making requests

### 6.1 From the same machine

```bash
# Health check
curl -i http://localhost:4221/

# Echo handler
curl -i http://localhost:4221/echo/hello-world

# User-Agent inspector
curl -i http://localhost:4221/user-agent

# Upload file
curl -i -X POST --data-binary @README.md http://localhost:4221/files/example.txt

# Download file
curl -i http://localhost:4221/files/example.txt
```

### 6.2 From another machine on the LAN

Replace `SERVER_IP` with the address discovered in Section 5. Use `https` and `-k` when TLS is enabled with a self-signed certificate.

```bash
# Health check over HTTPS
curl -k -i https://SERVER_IP:4221/

# Echo response
curl -k -i https://SERVER_IP:4221/echo/lan-test

# Upload a file from a remote workstation
curl -k -i -X POST --data-binary @notes.txt https://SERVER_IP:4221/files/notes.txt

# Download the same file
curl -k -i https://SERVER_IP:4221/files/notes.txt -o downloaded.txt
```

If the request hangs, verify that:

- The server is bound to `0.0.0.0` or the LAN IP.
- Firewalls on both machines permit TCP 4221.
- The client trusts the certificate (use `-k` or add the cert to the OS trust store for long-running tests).

## 7. Using the manual runner

```bash
source venv/bin/activate
python3 tests/manual_http_runner.py --base-url https://SERVER_IP:4221 --skip-stress
```

Flags allow you to skip smoke, load, or stress tiers. Provide `--base-url http://localhost:4221` for plain HTTP runs. Artifacts land in `.http-test-artifacts/`.

## 8. Running automated tests

```bash
source venv/bin/activate
python -m pytest                 # entire suite
python -m pytest -m integration  # server-spawning tests
```

Integration tests start the server as a subprocess, including TLS coverage when `certs/` contains a valid pair.

## 9. Graceful shutdown and health checks

### 9.1 Health check endpoint

The server exposes `GET /healthz` for monitoring and orchestration:

```bash
# Check server health
curl -i http://localhost:4221/healthz
```

- **200 OK**: Server is healthy and accepting traffic.
- **503 Service Unavailable**: Server is draining and will shut down soon.

### 9.2 Graceful shutdown behavior

When the server receives `SIGTERM` or `SIGINT` (Ctrl+C):

1. The server enters **draining mode** and stops accepting new work.
2. `/healthz` immediately returns `503 Service Unavailable` with body `draining`.
3. New connection attempts receive `503` responses.
4. In-flight requests are allowed to complete within the grace period.
5. After the grace period expires (default 30 seconds), the server exits.

### 9.3 Configuration

- `--socket-timeout <seconds>`: Maximum time for a single request (default 60).
- `--shutdown-grace-seconds <seconds>`: Grace period for draining (default 30).
- `HTTP_SERVER_SOCKET_TIMEOUT`: Environment variable override.
- `HTTP_SERVER_SHUTDOWN_GRACE_SECONDS`: Environment variable override.

### 9.4 Zero-downtime deployment workflow

For rolling updates or maintenance:

1. **Monitor health**: Poll `/healthz` to confirm the server is healthy (200 OK).
2. **Signal shutdown**: Send `SIGTERM` to the process (`kill -TERM <pid>`).
3. **Wait for draining**: Poll `/healthz` until it returns 503.
4. **Stop routing traffic**: Update load balancer or reverse proxy to remove this instance.
5. **Wait for completion**: The server will exit after in-flight requests finish.
6. **Start new instance**: Launch the updated server process.

Example polling script:

```bash
# Wait for server to enter draining state
while true; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:4221/healthz)
  if [ "$STATUS" = "503" ]; then
    echo "Server is draining"
    break
  fi
  sleep 0.5
done
```

## 10. Shutdown and cleanup

- Press `Ctrl+C` in the terminal running `main.py` to trigger graceful shutdown.
- The server will complete in-flight requests before exiting.
- Terminate the virtual environment session with `deactivate` when finished.
- Remove test files created under the configured `--directory` if they are no longer needed.

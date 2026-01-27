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

## 9. Shutdown and cleanup

- Press `Ctrl+C` in the terminal running `main.py` to stop the server.
- Terminate the virtual environment session with `deactivate` when finished.
- Remove test files created under the configured `--directory` if they are no longer needed.

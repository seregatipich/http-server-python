# pyhttpd — sample document (served over HTTPS)

You are reading a file streamed by `pyhttpd` over a TLS-terminated connection.
The server wraps its listening socket with an `ssl.SSLContext`
(`PROTOCOL_TLS_SERVER`) when started with a certificate and key, so this response
travelled encrypted end to end. The plaintext counterpart is `http-readme.txt`.

## Enabling TLS

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"
pyhttpd --directory ./data --port 8443 --cert cert.pem --key key.pem
curl --cacert cert.pem https://localhost:8443/https-readme.txt
```

## What TLS changes

- The transport is encrypted; the application protocol, routes, and headers are
  identical to the HTTP listener.
- `Strict-Transport-Security: max-age=63072000; includeSubDomains` instructs
  conformant browsers to keep using HTTPS for this origin.
- Invalid `--cert`/`--key` pairs are rejected at startup by configuration
  validation rather than failing on the first connection.

## Notes

TLS termination is the only transport difference — authentication, rate limiting,
CORS, conditional and range requests, and the `/metrics` endpoint behave the same
as over plaintext HTTP. Requires Python 3.11+. See `docs/USAGE_GUIDE.md`.

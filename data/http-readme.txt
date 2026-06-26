# pyhttpd — sample document (served over HTTP)

You are reading a file streamed by `pyhttpd`, a from-scratch threaded HTTP/1.1
server written in pure Python with zero runtime dependencies. This copy is being
served in plaintext HTTP; for the TLS-protected variant see `https-readme.txt`.

## What this server does

- Persistent HTTP/1.1 connections with keep-alive and `Connection: close` honored.
- Routes: `/`, `/echo/<message>`, `/user-agent`, `/healthz`, `/files/<path>`, and
  an opt-in Prometheus `/metrics` endpoint.
- File serving with `Content-Length`, `ETag`/`Last-Modified`, conditional `304`
  responses, `Range` requests (`206`/`416`), `HEAD`, `PUT`, and `DELETE`.
- gzip negotiation for text responses via `Accept-Encoding` quality factors.
- Security headers on every response: `Strict-Transport-Security`,
  `Content-Security-Policy`, and `X-Content-Type-Options`.

## Try it

```bash
pyhttpd --directory ./data --port 4221
curl http://localhost:4221/http-readme.txt
curl http://localhost:4221/echo/hello
```

## Going further

Authentication (`--auth-mode api-key|jwt`), rate limiting (`--rate-limit`), CORS
(`--cors-allowed-origins`), and metrics (`--metrics`) are all opt-in. Logging is
wired once through `pyhttpd.adapters.logging.setup.configure_logging`. Requires
Python 3.11+. See `docs/USAGE_GUIDE.md` for operational workflows.

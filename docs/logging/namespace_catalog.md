# Logging Namespace Catalog

This document defines the logging namespaces, components, and event names used throughout the HTTP server.

## Namespace Structure

All loggers follow the pattern: `http_server.<component>`

The `component` portion is automatically extracted by `CorrelationLoggerAdapter` and included in structured logs.

## Bootstrap & Startup

### `http_server.main`
**Module**: `main.py`  
**Events**:
- `server_starting` - Server initialization beginning
- `shutdown_signal_received` - SIGTERM or SIGINT received
- `server_stopped` - Server shutdown complete

### `http_server.bootstrap.logging`
**Module**: `server/bootstrap/logging_setup.py`  
**Events**:
- `logging_configured` - Logging system initialized
- `handler_created` - Log handler created (stdout or file)

### `http_server.bootstrap.config`
**Module**: `server/bootstrap/config.py`  
**Events**:
- `config_parsed` - CLI arguments parsed
- `config_override` - Environment variable override applied
- `config_default_used` - Default value used for configuration

## Lifecycle Management

### `http_server.lifecycle`
**Module**: `server/lifecycle/state.py`  
**Events**:
- `draining_started` - Server entering drain mode
- `worker_registered` - Worker thread registered
- `worker_unregistered` - Worker thread removed
- `shutdown_grace_expired` - Shutdown grace period timeout

## Transport Layer

### `http_server.transport.accept`
**Module**: `server/transport/accept_loop.py`  
**Events**:
- `server_listening` - Socket bound and listening
- `client_accepted` - New client connection accepted
- `connection_limit_reached` - Global connection limit hit
- `per_ip_limit_reached` - Per-IP connection limit hit
- `accept_error` - Error accepting connection
- `tls_handshake_started` - TLS handshake initiated
- `tls_handshake_complete` - TLS handshake successful
- `tls_handshake_failed` - TLS handshake error

### `http_server.transport.worker`
**Module**: `server/transport/worker.py`  
**Events**:
- `request_started` - Request processing beginning
- `request_line_parsed` - HTTP request line parsed
- `correlation_id_generated` - Correlation ID created for request
- `request_validation_failed` - Request validation error
- `request_complete` - Request processing finished
- `socket_closed` - Client socket closed
- `keepalive_detected` - Keep-alive connection detected
- `keepalive_terminated` - Keep-alive connection ended

### `http_server.transport.connection_limiter`
**Module**: `server/transport/connection_limiter.py`  
**Events**:
- `connection_acquired` - Connection slot acquired
- `connection_released` - Connection slot released
- `limit_enforced` - Connection rejected due to limit
- `per_ip_limit_enforced` - Per-IP connection rejected

## Pipeline Modules

### `http_server.pipeline.io`
**Module**: `server/pipeline/io.py`  
**Events**:
- `request_parsing_started` - Request parsing beginning
- `headers_parsed` - HTTP headers parsed
- `body_received` - Request body received
- `malformed_request` - Request parsing error
- `body_size_exceeded` - Request body too large

### `http_server.pipeline.router`
**Module**: `server/pipeline/router.py`  
**Events**:
- `route_matched` - Route matched for request
- `route_not_found` - No matching route
- `method_not_allowed` - HTTP method not supported

### `http_server.pipeline.rate_limiting`
**Module**: `server/pipeline/rate_limiting.py`  
**Events**:
- `rate_limit_checked` - Rate limit evaluation performed
- `rate_limit_allowed` - Request allowed by rate limiter
- `rate_limit_enforced` - 429 response sent
- `rate_limit_dry_run` - Dry-run mode: would have blocked
- `token_bucket_refilled` - Token bucket refill occurred

### `http_server.pipeline.validation`
**Module**: `server/pipeline/validation.py`  
**Events**:
- `request_validated` - Request validation passed
- `validation_failed` - Request validation failed
- `method_invalid` - HTTP method not in allowed set
- `path_invalid` - Request path validation failed
- `header_invalid` - Header validation failed

## Domain Utilities

### `http_server.domain.token_bucket`
**Module**: `server/domain/token_bucket.py`  
**Events**:
- `tokens_consumed` - Tokens deducted from bucket
- `tokens_refilled` - Bucket refilled with tokens
- `bucket_exhausted` - No tokens available
- `bucket_reset` - Bucket reset to initial state

### `http_server.domain.sandbox`
**Module**: `server/domain/sandbox.py`  
**Events**:
- `path_resolved` - Sandbox path resolution successful
- `traversal_blocked` - Path traversal attempt blocked
- `null_byte_detected` - Null byte in path detected
- `directory_access_blocked` - Directory access attempt blocked

### `http_server.domain.correlation_id`
**Module**: `server/domain/correlation_id.py`  
**Events**:
- `correlation_id_set` - Correlation ID stored in context
- `correlation_id_cleared` - Correlation ID removed from context

## Handlers

### `http_server.handlers.file`
**Module**: `server/handlers/file_handler.py`  
**Events**:
- `file_read_started` - File read operation beginning
- `file_read_complete` - File read successful
- `file_write_started` - File write operation beginning
- `file_write_complete` - File write successful
- `file_not_found` - Requested file not found
- `file_streaming_started` - Chunked file streaming initiated
- `file_chunk_sent` - File chunk transmitted

### `http_server.handlers.system`
**Module**: `server/handlers/system_handlers.py`  
**Events**:
- `healthz_check` - Health check endpoint called
- `echo_request` - Echo endpoint called
- `drain_request` - Drain endpoint called

## Security

### `http_server.security.tls`
**Module**: `server/security/tls.py`  
**Events**:
- `tls_enabled` - TLS termination enabled
- `cert_loaded` - TLS certificate loaded
- `key_loaded` - TLS private key loaded
- `cert_load_failed` - Certificate loading error
- `key_load_failed` - Private key loading error

### `http_server.security.headers`
**Module**: `server/security/headers.py`  
**Events**:
- `security_headers_applied` - Security headers added to response
- `hsts_header_added` - HSTS header added
- `csp_header_added` - CSP header added

## Structured Payload Contract

All logs must include:
- `correlation_id` (string, "-" if not in request context)
- `component` (string, extracted from logger name)
- `event` (string, from this catalog)

Optional fields (context-dependent):
- `client` (string, "ip:port")
- `connection_id` (string, UUID)
- `route` (string, matched route path)
- `status_code` (int, HTTP status)
- `limit_type` (string, "global" or "per_ip")
- `window_seconds` (float, rate limit window)
- `remaining_tokens` (int, tokens left in bucket)
- `bytes_in` (int, request body size)
- `bytes_out` (int, response body size)
- `duration_ms` (float, request processing time)
- `error_type` (string, exception class name)
- `errno` (int, system error number)
- `rate_limit_headers` (dict, subset of rate limit headers)

## Redaction Policy

The following data must never appear in logs:
- Request bodies
- Authorization header values
- Tokens, API keys, signatures
- Cookies
- File contents
- Query parameters named: token, key, signature, password
- Any 32+ character hex or base64 sequences

Use `redact_sensitive()` helper from `logging_setup.py` before logging string values.

## Performance Guardrails

Hot-path logging must use `isEnabledFor()` guards:
- `token_bucket.consume()`
- `connection_limiter.acquire/release()`
- `receive_request()` parsing loops
- `apply_rate_limit()` checks
- `resolve_sandbox_path()` validation
- File streaming generators

Example:
```python
if logger.isEnabledFor(logging.DEBUG):
    logger.debug("Token consumed", extra={"event": "tokens_consumed", "remaining": tokens})
```

## Testing Requirements

Every event in this catalog must have at least one test that:
1. Triggers the log emission
2. Asserts the event name matches
3. Validates required extra fields are present
4. Confirms message text is stable

Use `caplog` fixture for unit tests and `LogCaptureFixture` for integration tests.

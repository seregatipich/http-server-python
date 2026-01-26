---
title: Multi-Level Logging Implementation Plan
---

## Objectives
- Replace ad-hoc prints with structured logging at consistent severity levels.
- Provide operators with configurable verbosity for development, integration, and production modes.
- Ensure logging changes are testable and do not regress existing behavior.

## Current-State Review
1. Inventory every print statement and implicit error surface (main.py, tests, utilities).
2. Note code paths lacking diagnostics (socket accept loop, file I/O, compression, CLI parsing).
3. Document required context for troubleshooting (client address, request line, file path, exception type).

## Logging Architecture
1. Create a `logging_config.py` (or similar) that exports `configure_logging(level: str, destination: Optional[str])`.
2. Use the stdlib `logging` module with:
   - Root logger name `http_server` and child loggers per module (e.g., `http_server.server`).
   - Formatter: `'%(asctime)s %(levelname)s %(name)s :: %(message)s'` (24h ISO timestamps).
   - StreamHandler (stdout) by default; optional RotatingFileHandler when `destination` is provided.
3. Support levels DEBUG, INFO, WARNING, ERROR, CRITICAL; default INFO.
4. Load configuration once at process start (CLI entry point) and reuse existing logger instances everywhere else.

## Instrumentation Guidelines
1. Replace prints with logger calls at the appropriate severity:
   - DEBUG: socket accept/release, raw request summaries, compression decisions.
   - INFO: server startup/shutdown, served file paths, POST success.
   - WARNING: malformed requests, unsupported methods, client disconnects.
   - ERROR: I/O failures, gzip errors, thread spawn failures.
2. Use structured arguments (`logger.info("Served file", extra={"path": filepath, ...})`) where useful for downstream processing.
3. Guard logs to avoid leaking request bodies or sensitive file contents; log metadata instead.
4. Keep log statements close to decision points to aid debugging and avoid redundant noise.

## Configuration Surface
1. Extend CLI parser with `--log-level` (choices) and `--log-destination` (path or `stdout`).
2. Initialization flow:
   - Parse CLI args.
   - Call `configure_logging` before creating sockets.
   - Propagate selected level to worker threads; avoid reconfiguring logging per thread.
3. Document environment variable overrides if needed (e.g., `HTTP_SERVER_LOG_LEVEL`).

## Testing & Verification
1. Unit tests for `configure_logging` ensuring handlers/formatters match expectations (use `logging.getLogger` introspection).
2. Integration tests using `caplog` to assert that critical events produce messages at expected levels.
3. Performance tests to confirm logging does not degrade throughput (especially DEBUG floods).

## Rollout & Documentation
1. Update README with guidance on log levels, destinations, and operational recommendations.
2. Provide migration notes describing replaced print statements and how to enable verbose output.
3. After implementation, perform manual smoke tests to confirm logs appear in stdout and optional files.

---
title: chore/logging-prep → main merge roadmap
description: /plan-merge workflow for structured logging rollout
---

## 1. Context and scope
- **Source branch**: `chore/logging-prep`
- **Target branch**: `main`
- **Themes**: structured logging via `logging_config.py`, CLI logging flags with env fallbacks, log instrumentation in server lifecycle, README updates, new unit coverage for logging and compression helpers, docs added to repo (docs no longer gitignored).

## 2. Architectural audit
| Area | main | chore/logging-prep | Impact |
| --- | --- | --- | --- |
| Logging architecture | No centralized logger | Root logger `http_server` with rotating file or stdout handler, shared child loggers per module | Ensure single configuration at process start; avoid duplicate handler attachment in other modules. |
| CLI surface | directory/host/port only | Adds `--log-level`, `--log-destination`; env defaults `HTTP_SERVER_LOG_LEVEL`, `HTTP_SERVER_LOG_DESTINATION` | Downstream scripts must tolerate/ignore new flags; defaults preserve current behavior. |
| Observability in handlers | Print on error only | Structured DEBUG/INFO/WARNING logs across accept, parse, file ops, compression | Review for noise at DEBUG; no functional change expected. |
| Test coverage | No logging tests | Unit tests for logging config, CLI defaults/overrides, compression logging | Conflicts unlikely; keep markers consistent. |
| Repo hygiene | `docs/` ignored | `docs/` tracked to host plans | When merging, ensure root .gitignore aligns with documentation policy. |

Audit outcome: architecture remains single-process threaded server; logging initialization must stay centralized to prevent handler duplication.

## 3. Conflict hotspots and resolution intent
1. **.gitignore**: `docs/` removal may conflict with historical ignores. Keep tracking docs to ship roadmap/logging plan; if target wants ignore, retain plan files elsewhere before re-ignoring.
2. **README**: new logging flag docs could conflict with target edits. Keep operational guidance for log level/destination and merge any target additions manually.
3. **main.py**: logging instrumentation touches many lines; if target mutated handler logic, prefer keeping logging semantics while replaying any bug fixes from target.
4. **Environment defaults**: env-based defaults introduced; ensure no target code assumes absence of these variables.

## 4. Golden tests (stop-ship if red)
1. `source venv/bin/activate && python -m pytest tests/unit/test_logging_config.py`
2. `source venv/bin/activate && python -m pytest tests/unit/test_cli.py`
3. `source venv/bin/activate && python -m pytest tests/unit/test_compression.py`
4. `source venv/bin/activate && python -m pytest -m integration`
5. `source venv/bin/activate && python -m pytest` (full suite) once conflicts are resolved

## 5. Merge strategy
1. Update local `main`: `git fetch origin && git checkout main && git pull`.
2. Rebase `chore/logging-prep` onto `origin/main` to surface textual conflicts early; if history risk is high, fallback to merge but prefer rebase for clarity.
3. Resolve conflicts using section 3 priorities: preserve centralized logging setup and CLI flags; reconcile README and .gitignore intentionally.
4. Activate venv and install if needed: `source venv/bin/activate && pip install -r requirements.txt`.
5. Run golden tests (section 4). Address any regressions before proceeding.
6. Architectural verification: confirm only `main()` configures logging; other modules should import loggers without reconfiguring handlers.
7. Push and open/update PR summarizing logging capabilities and operational switches.

## 6. Risk log and mitigations
| Risk | Mitigation |
| --- | --- |
| Duplicate handlers if logging configured elsewhere | Enforce single call to `configure_logging` at startup; add guardrails in code review. |
| Log files uncontrolled growth | Rotating handler already configured; document 10 MB/5 backups defaults. |
| Tooling ignoring docs due to historical gitignore | Keep docs tracked; if policy demands ignore, relocate critical plans into tracked path before re-ignoring. |
| Debug-level noise under load | Default INFO; advise DEBUG only for troubleshooting. |

## 7. Definition of done
- Rebased/merged branch passes golden tests.
- README reflects logging options and defaults.
- .gitignore state decided and consistent with documentation policy.
- No duplicate logging configuration across modules; handlers verified clean.

---
title: test-plan-improvements → main merge roadmap
description: Detailed coordination plan per /plan-merge workflow
---

## 1. Context and scope
- **Source branch**: `test-plan-improvements`
- **Target branch**: `main`
- **Primary themes**: argparse-based CLI, expanded pytest suite (unit + integration + performance markers), manual load/stress runner, helper utilities under `tests/utils`, and dependency pinning via `requirements.txt`.

## 2. Architectural audit
| Area | main | test-plan-improvements | Impact |
| --- | --- | --- | --- |
| Server bootstrap | Manual `sys.argv` parsing and fixed host/port | `argparse`-backed configuration + exposed `parse_cli_args` API | Aligns with existing single-entry architecture; ensure no other module hardcodes host/port assumptions. |
| Test topology | Ad-hoc runner script | Layered pytest suite (unit/integration/perf) plus CLI runner for ops | Requires pytest configuration adoption and dependency installs (pytest/requests/etc.). |
| Observability/logging | Minimal | Still minimal | No conflict expected. |
| File service | Same behavior | Same behavior + tests verifying chunked streaming | Guarantees compatibility; no schema changes. |

Audit outcome: no architectural divergences, but downstream consumers must adopt the new CLI path and test tooling.

## 3. Conflict hotspots & resolutions
1. **`main.py` CLI args**: ensure no downstream tooling depends on the former positional `--directory` parsing. Plan to keep `parse_cli_args` public so scripts can reuse it; document in README.
2. **`README.md` setup/test instructions**: high likelihood of content conflicts if `main` changed documentation. Prefer manual merge keeping new testing instructions plus any `main` updates.
3. **`tests/manual_http_runner.py` rename**: file moved from `run_http_tests.py`; when merging, delete the legacy file only if absent on both branches to avoid accidental reintroduction.
4. **`requirements.txt` vs. existing dependency management**: ensure `main` doesn’t already specify deps elsewhere. If so, reconcile by consolidating into a single authoritative file.
5. **`pytest.ini` introduction**: confirm no conflicting pytest config exists on `main`. If there is, merge marker definitions and `addopts` carefully.

## 4. Golden tests
Run these after integrating to guarantee regressions are caught:
1. `source venv/bin/activate && python -m pytest tests/unit/test_cli.py` – locks CLI parsing contract.
2. `source venv/bin/activate && python -m pytest -m unit` – validates helper layers (compression, parsing, responses).
3. `source venv/bin/activate && python -m pytest -m integration` – verifies socket + chunked behavior with live server fixture.
4. `python tests/manual_http_runner.py --skip-load --skip-stress` – quick smoke plus persistence; extend to full load/stress once smoke passes.
5. Optional: `python tests/manual_http_runner.py` full run before release for assurance.

## 5. Merge strategy
1. **Update main locally**: `git fetch origin && git checkout main && git pull`.
2. **Rebase feature**: `git checkout test-plan-improvements && git rebase origin/main` to surface textual conflicts early. If rebase is risky, fallback to merge but prefer rebase for linear history.
3. **Resolve conflicts** per section 3, prioritizing: (a) preserve argparse + CLI exposure, (b) keep broadened README guidance, (c) ensure only one manual runner file remains, (d) consolidate dependency files.
4. **Install deps** inside the existing `venv`: `source venv/bin/activate && pip install -r requirements.txt` (skip if already satisfied).
5. **Execute golden tests** (section 4). Stop-ship if any fail.
6. **Architectural verification**: confirm `parse_cli_args` is used wherever server is launched (pytest fixture already uses CLI); ensure no hardcoded host/port remain.
7. **Push rebased branch**: `git push --force-with-lease origin test-plan-improvements` if rebase, otherwise normal push.
8. **Open/Update PR** summarizing new test infra and CLI entry point.

## 6. Risk log & mitigations
| Risk | Mitigation |
| --- | --- |
| Automations invoking `python main.py --directory` without host/port now rely on argparse defaults | Document defaults (`localhost`, `4221`) and update scripts to pass explicit flags if needed. |
| New dependencies may increase install time in CI | Cache `venv` or dependency wheels; requirements are minimal. |
| Manual runner rename might break docs/scripts referencing old path | README already updated; ensure any external docs follow suit. |

## 7. Decision points to monitor
- If `main` introduces conflicting CLI flags, re-run design review before merging.
- Should integration tests prove flakey on CI, consider reducing concurrency in fixtures or adding retries in `wait_for_port` helper.

## 8. Definition of done
- Rebased branch passes golden tests locally.
- README and tooling references aligned to `tests/manual_http_runner.py`.
- Single dependency specification (requirements.txt) adopted project-wide.
- Merge performed without introducing regressions or resurrecting deleted scripts.

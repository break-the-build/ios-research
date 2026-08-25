# Test Report

Refreshed 2026-08-25 from a local run of the full suite (the original report
was generated during the phase-10 final audit and has been updated as the
suite grew).

## Summary

- **Result:** 1,691 tests across 110 test modules; full suite green in CI
  (Ubuntu + macOS × Python 3.10/3.12, `-m "not native"`)
- **Coverage:** ~89% (branch coverage enabled) across `ios_research`
  (~15.3k statements); CI enforces a hard floor of 85%
- **Runner:** `pytest` — deterministic via a frozen clock
  (`IOS_RESEARCH_FROZEN_TIME`); native-harness tests are opt-in via the
  `native` marker and require a real macOS toolchain
- **Command:** `pytest --cov=ios_research --cov-report=term-missing`

Timing-sensitive behaviors are asserted structurally, not by wall-clock
comparison: fan-out via observed peak concurrency
(`test_parallel.py`, `test_crash_triage.py`; #274) and pipeline stage
coverage via per-stage metrics (`test_goals_bounty_coverage.py`; #275).

## Test suites

The repo carries 110 test modules covering every command group and target
family (`pytest --collect-only -q | tail -1` for the live count). The original
phase suites below are retained for history:

| Suite | Focus |
|-------|-------|
| `test_foundation.py` | exit codes, hashing, ids, config, safety, workspace, target interface, CLI framework |
| `test_cli_runtime.py` | init/config/device/target/experiment; artifact store |
| `test_corpus_fuzz.py` | mutation determinism, corpus ops, crash dedup, fuzz determinism + resume equivalence |
| `test_audio_module.py` | WAV/MP3/AAC/ALAC targets, format-aware mutation, deterministic diagnostics |
| `test_crash_triage.py` | ddmin, reproduce, classify, minimize (+regression corpus), compare |
| `test_analysis.py` | evidence-gated exploitability indicators; never fabricates code-exec |
| `test_differential.py` | v1/v2 transitions, regression detection, diff reproducibility |
| `test_agent.py` | schema contract, agent status/run pipeline, determinism, JSON everywhere |
| `test_report.py` | report sections, evidence tracing, validation (missing/overclaim/forbidden) |
| `test_research.py` | 12-stage orchestration, resume equivalence, resource limits, confirmation gate |
| `test_integration_cli.py` | end-to-end CLI artifact chain + final-verification command sweep |
| `test_regression.py` | replay regression corpus; known inputs still crash with recorded signature |

Later additions include suites for every mock target family (`test_<family>_module.py`),
real-signal targets (`test_mac_target.py`, `test_device_target.py`), engine
features (`test_directed.py`, `test_stateful*.py`, `test_fuzz_*.py`),
platform tooling (`test_staticscan.py`, `test_xcode*.py`, `test_nday.py`,
`test_srd.py`, `test_supply.py`, `test_races.py`), and documentation
contract tests (`test_cli_reference.py`, schema-sync in `test_agent.py`).

## Test types

- **Unit** — engines and core services in isolation.
- **Integration** — command layer through the real CLI with `--json`.
- **End-to-end** — full artifact chain `experiment → crash → minimized →
  analysis → report`, and a complete `research run`.
- **Regression** — regression-corpus replay guarding known crash behavior.
- **Mutation-tested** — critical logic was verified by targeted mutation
  testing during optimization rounds; eight real test gaps found and closed.
  Safety-critical exploitability/validation logic has no surviving mutants.

## Determinism & resumability (explicitly tested)

- Fuzzing is reproducible across fresh workspaces.
- A chunked (paused/resumed) fuzz run matches a single run exactly.
- Differential and full research runs are reproducible.
- A chunked research run matches a single run's summary exactly.

## Final verification

All commands from the RUN-ALL final-verification list execute successfully with
`--json` (see `test_integration_cli.py::test_final_verification_commands_all_json`
and the manual CLI sweep during the audit): `--help`, `doctor`, `init`,
`experiment create`, `corpus create`, `fuzz start`, `crash list`,
`crash minimize`, `analyze`, `diff`, `report create`, `research run`,
`research summarize`, `agent status`.

## Documentation contract

Two tests pin generated docs to the live CLI so they cannot drift silently:

- `tests/test_cli_reference.py` — [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)
  matches `python tools/gen_cli_reference.py --check`
- `tests/test_agent.py::test_committed_cli_schema_matches_generator` —
  [docs/cli-schema.json](docs/cli-schema.json) matches `build_cli_schema()`

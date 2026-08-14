# Test Report

Generated during phase 10 (final audit).

## Summary

- **Result:** 197 passed, 0 failed
- **Branch coverage:** 95% (statements + branches) across `ios_research`
- **Runner:** `pytest` (Python 3.14), deterministic via a frozen clock
- **Command:** `pytest --cov=ios_research --cov-report=term-missing`

## Test suites

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
| `test_mutation_weights.py` | configurable strategy weighting; byte-identical to uniform when unset |
| `test_fuzz_throughput.py` | batched-persistence equivalence; memoized pool; crash-count batching |
| `test_command_handlers.py` | CLI handlers (corpus/audio/agent/research/diff/report/config) via `main` |
| `test_logging_output.py` | structured logging levels/redaction/file output; `Result` renderer |
| `test_edge_paths.py` | context/report/fuzz error-handling and control-transition edge paths |

## Test types

- **Unit** — engines and core services in isolation.
- **Integration** — command layer through the real CLI with `--json`.
- **End-to-end** — full artifact chain `experiment → crash → minimized →
  analysis → report`, and a complete `research run`.
- **Regression** — regression-corpus replay guarding known crash behavior.
- **Mutation-tested** — critical logic is verified by targeted mutation testing;
  five real test gaps found and closed (config deep-merge, config-hash width,
  differential regression direction, differential `differs` flag, report
  empty-section validation). Safety-critical exploitability/validation logic has
  no surviving mutants.

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

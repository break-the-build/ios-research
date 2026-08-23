# ios-research × experiment-loop environments

These modules bind ios-research to the [`experiment-loop`](../../..) engine so it
can autonomously optimize real framework behavior. Each environment implements
`run(config, samples, seed) -> Observation` and exposes the metrics declared by
its goal in [`goals/`](../../goals).

Read the [goal portfolio policy](../../goals/README.md) before interpreting a
result. The current environments are deterministic simulations or local quality
gates unless the policy explicitly classifies them as authorized-target
validation; simulator results must not be reported as real-device performance,
operational cost, or verified vulnerability findings.

## Usage

```bash
# from the ios-research repo root, with both packages importable
PYTHONPATH=/path/to/experiment-loop \
  python -m experiment_loop run goals/06-fuzz-effectiveness.json \
    --load tools/experiment_loop/ios_research_env.py --samples 40 --generations 5
```

`--load` adds this directory to `sys.path` and imports the `ios_env` package,
which registers every environment below.

## Environments

| Environment | Goals | Knobs | Primary metric | Gradient |
|-------------|-------|-------|----------------|----------|
| `ios_research_fuzzer` | 05, 06 | 7 strategy weights + `case_budget` | `unique_crashes_per_100k_cases` / `executions_per_second` | strong (effectiveness); pure-compute throughput |
| `ios_research_fuzzer_engine` | 05 (`05-fuzz-throughput-engine.json`) | 7 strategy weights + `max_cases` | `executions_per_second` | **real-engine** throughput incl. persistence I/O |
| `ios_research_corpus` | 07 | 7 strategy weights | `coverage_per_input` | moderate |
| `ios_research_crash_analysis` | 08, 11 | `sig_frames`, `use_exception`, `use_access` | `deduplication_f1` | strong (0.63 → 1.00) |
| `ios_research_differential` | 12 | 7 strategy weights + `corpus_size` | `actionable_differences_per_1000_cases` | strong |
| `ios_research_minimizer` | 09 | `start_n`, `min_chunk` | `median_input_reduction` | flat (ddmin already optimal) |
| `ios_research` | 13 | 7 strategy weights + `max_cases` | `actionable_findings_per_dollar` | cost/quality trade-off |
| `ios_research_agent` | 14, 15 | `max_cases`, `weight_structure_aware`, `minimize` | `successful_goal_completion_rate` / `quality_per_dollar` | strong (budget↔quality) |
| `ios_research_reporting` | 17 | `minimize_before_report`, `reproduce_before_report` | `report_quality_score` | revealed reports failed the ≥0.95 evidence bar; fixed |

Notes:

- All environments exercise **mock targets and in-process code only** — no new
  capability, fully within the authorized-research safety boundary.
- Measurements mirror the real `FuzzEngine` inner step
  (`mutation.mutate` → `target.execute`), so improvements the loop finds map
  directly onto framework configuration (e.g. `fuzz.strategy_weights`). The
  `ios_research_fuzzer_engine` variant instead runs the **whole** engine
  (`FuzzEngine.advance` against a throwaway workspace), so its
  `executions_per_second` includes artifact/corpus/crash persistence — the disk
  I/O that dominates real fuzzing throughput.
- `ios_research_crash_analysis` and `ios_research_minimizer` show that the
  current defaults are already at (or near) the optimum for their primary
  metric — the loop correctly reports little/no headroom, which is a useful
  negative result, not a failure.

## Design principle: no gameable knobs

Knobs are only exposed when they map to a genuine behavioral choice. For
example, the minimizer's input padding is a fixed constant rather than a knob,
so the optimizer cannot inflate the reduction ratio by padding more.

## Not yet implemented

Goals whose properties are already exact-by-construction or have no runtime knob
search — test-suite coverage (01/02), CLI reliability/performance (03/04),
reproduction rate (10), reporting (17), security (19), documentation (20), and
the framework reliability / experiment reproducibility variants (16/18) — are
intentionally omitted; there is no honest knob→metric gradient to optimize. See
`docs/EXPERIMENT-LOOP-RESULTS.md` for the rationale.

## Goal-file note

`goals/13-research-efficiency.json` originally constrained
`reproducible_crash_rate` without listing it in its own `metrics`, so
experiment-loop rejected the goal during validation. That metric was added to
the goal's metric list (the `ios_research` environment reports it) so the goal
validates and runs.

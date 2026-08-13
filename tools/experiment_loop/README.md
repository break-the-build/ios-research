# ios-research × experiment-loop environments

These modules bind ios-research to the [`experiment-loop`](../../..) engine so it
can autonomously optimize real framework behavior. Each environment implements
`run(config, samples, seed) -> Observation` and exposes the metrics declared by
its goal in [`goals/`](../../goals).

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
| `ios_research_fuzzer` | 05, 06 | 7 strategy weights + `case_budget` | `unique_crashes_per_100k_cases` / `executions_per_second` | strong (effectiveness) |
| `ios_research_corpus` | 07 | 7 strategy weights | `coverage_per_input` | moderate |
| `ios_research_crash_analysis` | 08, 11 | `sig_frames`, `use_exception`, `use_access` | `deduplication_f1` | strong (0.63 → 1.00) |
| `ios_research_differential` | 12 | 7 strategy weights + `corpus_size` | `actionable_differences_per_1000_cases` | strong |
| `ios_research_minimizer` | 09 | `start_n`, `min_chunk` | `median_input_reduction` | flat (ddmin already optimal) |

Notes:

- All environments exercise **mock targets and in-process code only** — no new
  capability, fully within the authorized-research safety boundary.
- Measurements mirror the real `FuzzEngine` inner step
  (`mutation.mutate` → `target.execute`), so improvements the loop finds map
  directly onto framework configuration (e.g. `fuzz.strategy_weights`).
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
search (test-suite coverage, CLI reliability, reproduction rate, reporting,
security, documentation, framework reliability) are intentionally omitted — see
`docs/EXPERIMENT-LOOP-RESULTS.md` for the rationale and future-work notes.

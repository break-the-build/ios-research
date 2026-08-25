# Mock-campaign performance baseline

This baseline was captured with `benchmark profile` on the development macOS
host at commit `97028d8`, using `mock:parser`, 10,000 cases, and seeds 0–2.
It is a local decision input, not a universal throughput claim; repeat it on
the intended machine before changing the implementation.

| Stage | Mean seconds | Mean share of wall time |
| --- | ---: | ---: |
| Persistence | 0.797 | 67.7% |
| Mutation | 0.097 | 8.4% |
| Mock target execution | 0.060 | 5.2% |
| Sanitizer/report parsing | 0.000 | 0.0% |
| End-to-end wall time | 1.170 | 100% |

The three wall-time samples were 1.119 s, 1.386 s, and 1.004 s. Persistence
made 4,513, 4,977, and 4,127 timed calls respectively. The dominant work is
therefore filesystem/metadata persistence, not a Python CPU loop suitable for
a Rust port. Mutation is below the 20% Rust-investigation threshold defined in
[PERFORMANCE.md](PERFORMANCE.md).

## Resulting recommendations

1. Measure and reduce corpus/artifact write amplification while preserving
   crash durability and deterministic resume semantics.
2. Add a separately authorized native-harness profile that breaks out process
   startup, sanitizer/report parsing, framework decode, and persistence. Do
   not infer these costs from mock targets.
3. Revisit a Rust prototype only after a stable CPU-owned stage exceeds the
   documented threshold across representative workloads.

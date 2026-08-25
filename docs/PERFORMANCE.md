# Performance baselines and Rust acceleration criteria

Run a deterministic, bounded mock-target baseline before proposing a Rust port:

```bash
ios-research benchmark profile --target mock:parser --max-cases 1000 --seed 0 --json
```

The command uses a temporary workspace and reports wall time for mutation,
target execution, sanitizer/report parsing, and persistence. Mock profiles
intentionally report zero sanitizer/report parsing time; profile a separate,
authorized native campaign when evaluating harness and sanitizer overhead.

## Decision rule

Do not rewrite the CLI or campaign orchestration wholesale. Consider a Rust
implementation only when a stable, Python-owned stage accounts for at least
20% of end-to-end wall time across three representative runs and a prototype
can show at least a 2x reduction for that stage without changing deterministic
inputs, JSON output, or persisted artifacts.

Candidate stages are mutation, corpus hashing/deduplication, minimization
scheduling, and sanitizer-report parsing. Native harness execution, framework
decode time, sanitizer startup, and disk I/O should remain in their existing
native/toolchain boundary unless their own measurements show a different
bottleneck.

Any acceleration prototype must sit behind a stable interface and include
parity, deterministic-output, and representative-workload comparison tests.

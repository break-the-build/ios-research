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

`benchmark profile` also reports a persistence breakdown: input writes, corpus
manifests, crash records, session checkpoints, and other metadata. Corpus
manifests use compact deterministic JSON to reduce metadata serialization and
I/O; this does not alter their data model or resume semantics.

Any acceleration prototype must sit behind a stable interface and include
parity, deterministic-output, and representative-workload comparison tests.

## Authorized native-harness measurement

After building a local `mac:*` harness and confirming authorization, run:

```bash
ios-research benchmark native-profile --target mac:imageio --max-cases 10 \
  --acknowledge-authorized-use --json
```

This is opt-in and retains no campaign workspace or input artifacts. It reports
an empty-input process-startup estimate, target execution after subtracting that
estimate, and sanitizer-report parsing. Compare its stage shape with the mock
baseline; do not combine their absolute throughput claims.

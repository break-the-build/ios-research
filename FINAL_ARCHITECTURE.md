# Final Architecture

`ios-research` is a deterministic, CLI-driven framework for authorized iOS
security research, operable by both humans and LLM agents. This document
describes the system as built across phases 00–10.

## Layered view

```
CLI (argparse dispatch, global flags, Result envelope)
    commands/*  ── one module per command group
        │
        ▼
Domain engines
    fuzz.FuzzEngine        corpus.CorpusStore     crashes.CrashStore
    triage.Triage          analysis.Analyzer      differential.Differential…
    report.ReportGenerator research.Orchestrator  agent.Agent
        │
        ▼
Core services
    workspace (atomic JSON I/O)   config (+hash)   artifacts (content-addressed)
    experiment / devices          targets (registry + mock/audio + v2)
    clock   ids   hashing   logging(redaction)   safety   errors(exit codes)
```

## Determinism & reproducibility

- IDs and hashes derive from stable inputs (`ids`, `hashing`).
- Timestamps flow through an injectable `clock` (freezable via
  `IOS_RESEARCH_FROZEN_TIME`).
- Fuzzing uses a seeded RNG and a **fixed per-session base set**, making runs
  reproducible and resume-invariant.
- Mock targets compute outcomes and synthetic diagnostics purely from input
  bytes, so every crash reproduces exactly.

## Resumability

All state persists as JSON under `.ios-research/`, written atomically
(`os.replace`). Fuzz sessions and research runs advance a cursor and can be
paused/resumed with identical end-state to a single run (verified by tests).

## Artifact chain

    experiment ──▶ testcase ──▶ crash ──▶ minimized testcase
                                   │
                                   ├──▶ analysis ──▶ report
                                   └──▶ (regression corpus)

Reports carry an `evidence` block that traces every claim back to experiment id,
input/minimized hashes, crash signature, analysis id, and diagnostics.

## Targets

One interface (`prepare → execute → collect → cleanup`) backs every target:

- `mock:parser` / `mock:parser-v2` — deterministic record parser (+ a version
  with fixes and one regression for differential testing)
- `audio:{wav,mp3,aac,alac}` — mock audio parsers sharing a defect model

Real authorized research devices can be added behind the same interface
(`docs/RESEARCH-DEVICE.md`).

## Machine interface

`schema.build_cli_schema()` emits a complete, deterministic description of the
CLI (commands, exit codes, artifact locations, lifecycle, classifications,
safety boundary), committed at `docs/cli-schema.json` and surfaced via
`agent inspect`.

## Safety

`safety.py` is the single source of truth for allowed vs forbidden capabilities.
Destructive operations require `--yes`. Logs redact secrets. See
`SECURITY_AUDIT.md`.

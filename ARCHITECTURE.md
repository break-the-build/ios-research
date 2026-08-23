# Architecture

`ios-research` is a single, CLI-driven framework for authorized iOS security
research. It is built from small, focused modules and is designed to be driven
both by human researchers and by LLM agents.

## Principles

- **Deterministic & reproducible** — identifiers, hashes, and (via an injectable
  clock) timestamps are derived from stable inputs. The same experiment inputs
  produce the same artifacts.
- **Resumable** — all state lives on disk as JSON under a workspace, written
  atomically to avoid corruption.
- **Machine-readable** — every command returns a stable `Result` envelope that
  renders as human text or, with `--json`, as deterministic JSON.
- **Modular targets** — research targets implement one interface, so new attack
  surfaces (and, later, real authorized research devices) plug in without
  changing the pipeline.
- **Safety first** — a single `safety` module declares and enforces the
  authorized-research boundary.

## Core modules (`src/ios_research/`)

| Module | Responsibility |
|--------|----------------|
| `errors.py` | Exception hierarchy and stable process exit codes |
| `hashing.py` | SHA-256 helpers, canonical JSON, config hashing |
| `ids.py` | Deterministic identifier generation |
| `clock.py` | Injectable clock (freezable for tests/CI) |
| `output.py` | `Result` envelope + human/JSON rendering |
| `logging_util.py` | Structured logging with secret redaction |
| `safety.py` | Allowed/forbidden capabilities + enforcement |
| `workspace.py` | On-disk workspace layout and atomic JSON I/O |
| `config.py` | Layered configuration + deterministic config hash |
| `coverage.py` | Optional stable-feature adapter contract and validation |
| `devices.py` | Device abstraction + mock devices |
| `experiment.py` | Experiment model and store |
| `targets/` | Target interface, registry, deterministic mock parser |
| `context.py` | Shared execution context for handlers |
| `cli.py` | Argument parsing and command dispatch |
| `commands/` | One module per command group |

## Target lifecycle

    prepare() -> execute(input) -> collect_result() -> cleanup()

`execute()` returns a normalized `ExecResult` with an `Outcome`
(`accepted`/`rejected`/`timeout`/`crash`/`abnormal`) and, for crashes,
deterministic `Diagnostics`.

Targets may additionally implement `coverage_features(input, result)` to return
stable, opaque feature IDs from an authorized instrumentation adapter. The fuzz
engine retains inputs that add a new feature, selects retained inputs with a
persisted deterministic fair schedule, and records feature evidence in corpus
metadata. A target without this optional hook follows the original fixed-base
schedule; coverage is never inferred from crash diagnostics. Corpus minimization
preserves at least one input for every recorded coverage feature.

## Artifact lifecycle (built up across phases)

    experiment -> corpus -> testcase -> fuzz execution -> crash
      -> minimized testcase -> analysis -> report

## Workspace layout

    .ios-research/
      workspace.json       # marker + framework/schema version
      config/  experiments/  devices/  targets/  corpus/
      crashes/  artifacts/  analysis/  diffs/  research/  logs/

See `docs/PHASE-STATUS.md` for build progress and `SECURITY.md` for the safety
boundary.

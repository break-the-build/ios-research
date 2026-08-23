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
  authorized-research boundary; all workspace I/O is path-contained so
  externally influenced identifiers cannot escape the workspace.

## Core modules (`src/ios_research/`)

Grouped by responsibility; one command module per CLI group under
`commands/`.

**Foundation**

| Module | Responsibility |
|--------|----------------|
| `errors.py` | Exception hierarchy and stable process exit codes |
| `hashing.py` | SHA-256 helpers, canonical JSON, config hashing |
| `ids.py` | Deterministic identifier generation |
| `clock.py` | Injectable clock (freezable for tests/CI) |
| `output.py` | `Result` envelope + human/JSON rendering |
| `logging_util.py` | Structured logging with secret redaction |
| `safety.py` | Allowed/forbidden capabilities + enforcement |
| `workspace.py` | Workspace layout, atomic JSON I/O, path containment |

**State & pipeline**

| Module | Responsibility |
|--------|----------------|
| `config.py` | Layered configuration + deterministic config hash |
| `artifacts.py` | Content-addressed artifact store (SHA-256) |
| `experiment.py` | Experiment model and store |
| `corpus.py` / `coverage.py` | Corpus store; coverage-feature contract |
| `mutation.py` / `dictionary.py` / `grammar.py` | Deterministic mutation; dictionaries; mutator plugins |
| `fuzz.py` | Resumable fuzz engine (bounds, batching, dedup) |
| `crashes.py` / `triage.py` | Crash records + signature dedup; reproduce/minimize/classify |
| `analysis.py` / `findings.py` | Evidence-gated exploitability indicators; finding ledger |
| `differential.py` / `matrix.py` / `betadiff.py` | Version diffs; device/OS matrix runs; beta differential |
| `research.py` | 12-stage resumable orchestration |
| `report.py` / `bounty.py` | Responsible-disclosure reports; bounty evidence packs |
| `sanitizers.py` / `engine_import.py` | Sanitizer profiles; external engine result import |
| `harness.py` / `harness_runner.py` | Generated-harness candidates; isolated smoke execution |
| `devices.py` / `targets/` | Device abstraction; target interface + implementations |

**Detection & validation (defensive)**

| Module | Responsibility |
|--------|----------------|
| `detection.py` + `signatures/` | YARA-style rule engine + built-in capability-indicator rules |
| `cvereg.py` | Known-CVE patch-regression registry and validation |
| `oracles.py` / `macoracles.py` / `flagcapture.py` | Objective verification oracles for lab experiments |
| `lockdown.py` | Paired standard/lockdown-target comparison |
| `nettransport.py` | Loopback-only transport harness |
| `advisories.py` / `surface.py` / `targetflags.py` / `spoints.py` | Advisory notes; attack-surface inventory; target-flag capture; security points |

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
      config/  experiments/  devices/  targets/  corpus/  fuzz/
      crashes/  artifacts/  analysis/  diffs/  research/  reports/
      harnesses/  spoints/  findings/  matrices/  advisories/
      known-cve/           # CVE patch-regression registry (cvereg)
      logs/

See `docs/PHASE-STATUS.md` for build progress and `SECURITY.md` for the safety
boundary.

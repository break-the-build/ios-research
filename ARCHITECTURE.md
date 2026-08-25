# Architecture

`ios-research` is a single, CLI-driven framework for authorized iOS security
research. It is built from small, focused modules and is designed to be driven
both by human researchers and by LLM agents.

## Principles

- **Deterministic & reproducible** — identifiers, hashes, and (via an injectable
  clock, freezable with `IOS_RESEARCH_FROZEN_TIME`) timestamps are derived from
  stable inputs. The same experiment inputs produce the same artifacts.
- **Resumable** — all state lives on disk as JSON under a workspace, written
  atomically (`os.replace`) to avoid corruption.
- **Machine-readable** — every command returns a stable `Result` envelope that
  renders as human text or, with `--json`, as deterministic JSON.
- **Modular targets** — research targets implement one interface, so new attack
  surfaces plug in without changing the pipeline.
- **Safety first** — a single `safety` module declares and enforces the
  authorized-research boundary; all workspace I/O is path-contained so
  externally influenced identifiers cannot escape the workspace.

## Layered view

```
CLI (argparse dispatch, global flags, Result envelope)
    commands/*  ── one module per command group
        │
        ▼
Domain engines
    fuzz.FuzzEngine      corpus.CorpusStore     crashes.CrashStore
    triage.Triage        analysis.Analyzer      differential.Differential …
    report.ReportGenerator  research.Orchestrator  agent.Agent
        │
        ▼
Core services
    workspace (atomic JSON I/O)   config (+hash)   artifacts (content-addressed)
    experiment / devices          targets (registry + target families)
    clock   ids   hashing   logging(redaction)   safety   errors(exit codes)
```

## Core modules (`src/ios_research/`)

Grouped by responsibility; one command module per CLI group under `commands/`.
The full command surface is described in [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md).

**Foundation** — `errors` (exit codes), `hashing`, `ids`, `clock`, `output`
(envelope rendering), `logging_util` (secret redaction), `safety` (allowed vs
forbidden capabilities + enforcement), `workspace` (layout, atomic JSON I/O,
path containment), `config`, `context`.

**State & pipeline** — `artifacts` (content-addressed store), `experiment`,
`corpus`/`coverage`/`coverage_report`, `mutation`/`dictionary`/`grammar`/
`llmmutate`/`plugins_builtin`, `fuzz` (+ `directed`, `executors`, `engines`,
`parallel`, `stateful` for sequence fuzzing), `crashes`/`triage`,
`analysis`/`findings`/`evidence`, `differential`/`matrix`/`betadiff`,
`research` (12-stage resumable orchestration), `report`/`bounty`,
`sanitizers`, `harness`/`harness_runner`, `engine_import`, `devices`/
`vdevices`, `targets/` (target interface + implementations).

**Real-signal & platform tooling** — `staticscan` (Mach-O/dyld-cache census,
parser fingerprinting, call-graph export), `ipa_analysis`, `ipswdiff`,
`machmsg` (kernel message builder/parser), `xcode` (test-plan adapter),
`suites`, `targetsdk` (custom-target SDK), `supply` (dependency audit),
`races` (TSan report import), `mitigation` (MIE/MTE profiles), `proximity`,
`srd` (Security Research Device gating), `profiling`, `observability`.

**Detection & validation (defensive)** — `detection` + `signatures/`
(YARA-style capability-indicator rules), `cvereg` (known-CVE patch-regression
registry), `oracles`/`macoracles`/`flagcapture` (objective verification
oracles), `lockdown` (paired standard/lockdown comparison),
`nettransport` (loopback-only transport harness), `advisories`/`surface`/
`targetflags`/`spoints` (advisories; attack-surface inventory; Target-Flag
capture; security points), `campaign`/`campaign_sync` (distributed corpus
sync), `schema` (machine-readable CLI description), `agent` (agent entry
points), `cli` (dispatch).

## Machine interface

`schema.build_cli_schema()` emits a complete, deterministic description of the
CLI (commands, exit codes, artifact locations, lifecycle, classifications,
safety boundary). It is committed at [docs/cli-schema.json](docs/cli-schema.json),
surfaced via `ios-research agent inspect`, and rendered as human documentation
in [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) (regenerate with
`python tools/gen_cli_reference.py`). Tests verify both stay current after CLI
changes.

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

Target families range from CI-safe mocks (e.g. `mock:parser`, `audio:*`,
`messaging:*`) to real-signal opt-ins: in-process macOS framework harnesses
(`mac:*`, see [docs/MAC-FUZZING.md](docs/MAC-FUZZING.md)) and black-box
on-device confirmation targets (`ios-device:*`, see
[docs/ON-DEVICE-TARGET.md](docs/ON-DEVICE-TARGET.md)). New device targets plug
in behind the same interface ([docs/RESEARCH-DEVICE.md](docs/RESEARCH-DEVICE.md)).

## Artifact lifecycle

    experiment -> corpus -> testcase -> fuzz execution -> crash
      -> minimized testcase -> analysis -> report
                               │
                               └──> (regression corpus)

Reports carry an `evidence` block that traces every claim back to experiment
id, input/minimized hashes, crash signature, analysis id, and diagnostics.

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

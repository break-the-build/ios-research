# ios-research — Phase Status

Tracks execution of the development phases defined in `docs/PROMPT-RUN-ALL.md`.

Statuses: `NOT_STARTED` · `IN_PROGRESS` · `BLOCKED` · `COMPLETE`

| Phase | Prompt | Status | Started | Completed | Tests | Commit | Notes |
|-------|--------|--------|---------|-----------|-------|--------|-------|
| 00 | architecture | COMPLETE | 2026-08-13 | 2026-08-13 | 20 pass | _pending_ | Foundation: errors/exit-codes, hashing, ids, clock, output envelope, structured logging w/ redaction, safety boundary, workspace, config, target interface + mock parser, device/experiment models, CLI framework, docs. |
| 01 | cli-runtime | COMPLETE | 2026-08-13 | 2026-08-13 | 32 pass | _pending_ | init/config/device/target/experiment commands; artifact store; global flags; mock devices/targets. |
| 02 | corpus-fuzzing | COMPLETE | 2026-08-13 | 2026-08-13 | 48 pass | _pending_ | 7 deterministic mutation strategies; corpus create/import/list/inspect/dedupe/minimize; crash store w/ signature dedup; resumable, reproducible fuzz engine (start/stop/pause/resume/status/stats). |
| 03 | audio-module | COMPLETE | 2026-08-13 | 2026-08-13 | 71 pass | _pending_ | WAV/MP3/AAC/ALAC mock targets w/ shared defect model; format-aware structure mutation; target audio list/inspect; fuzz --target audio:<fmt>; RESEARCH-DEVICE.md. |
| 04 | crash-triage | COMPLETE | 2026-08-13 | 2026-08-13 | 79 pass | _pending_ | crash list/show/reproduce/minimize/classify/compare; ddmin delta-debugging preserving signature; regression corpus; diagnostics persisted per crash. |
| 05 | exploitability-analysis | COMPLETE | 2026-08-13 | 2026-08-13 | 85 pass | _pending_ | analyze <id> / analyze --batch / analysis show/list; conservative evidence-gated exploitability indicators (CRASH_ONLY..CODE_EXECUTION); memory-safety class; open questions; never fabricates code-exec. |
| 06 | differential-testing | COMPLETE | 2026-08-13 | 2026-08-13 | 91 pass | _pending_ | mock:parser-v2 (fixes + regression); diff create/run/compare/report; transition classification (NORMAL->CRASH etc.); regression detection; reproducible diff experiments. |
| 07 | llm-agent | COMPLETE | 2026-08-13 | 2026-08-13 | 97 pass | _pending_ | agent status/inspect/schema/run/experiment/analyze; machine-readable docs/cli-schema.json; AGENTS.md; deterministic bounded pipeline; --json on every command. |
| 08 | vulnerability-reporting | COMPLETE | 2026-08-13 | 2026-08-13 | 105 pass | _pending_ | report create/show/validate/export; 18 required sections; evidence traces to artifacts/hashes/experiment; validation catches missing evidence, overclaims, forbidden content; Markdown + JSON; Apple disclosure template. |
| 09 | research-orchestration | COMPLETE | 2026-08-13 | 2026-08-13 | 113 pass | _pending_ | research create/run/status/pause/resume/summarize; 12-stage resumable pipeline; resource limits (runtime/workers/storage/testcases); --yes confirmation gate; full summary + next steps. |
| 10 | audit-hardening | NOT_STARTED | | | | | audit + final docs |

## Safety boundary

All phases respect the authorized-research boundary declared in
`src/ios_research/safety.py` and documented in `SECURITY.md`. No exploit
generation, persistence, surveillance, or sandbox/TCC bypass is implemented.

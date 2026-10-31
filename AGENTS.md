# Operating ios-research as an LLM Agent

`ios-research` is designed to be driven by LLM agents such as Claude Code. Every
command supports `--json` and returns a stable envelope, and the full CLI is
described in a machine-readable schema.

## Contract

- **JSON everywhere**: pass `--json` to any command. The envelope is:

  ```json
  { "ok": true, "command": "...", "data": {}, "messages": [],
    "error": null, "exit_code": 0 }
  ```

- **Stable exit codes**: `0 OK`, `1 ERROR`, `2 USAGE`, `3 NOT_FOUND`,
  `4 VALIDATION`, `5 SAFETY`, `6 INTERRUPTED`, `7 STATE`.
- **Schema**: `ios-research agent inspect --json` returns the full schema, also
  committed at [`docs/cli-schema.json`](docs/cli-schema.json). Regenerate with
  `ios-research agent schema`.
- **Workspace pinning**: commands resolve their workspace as explicit
  `--workspace P` flag > `$IOS_RESEARCH_WORKSPACE` > nearest `.ios-research/`
  above the cwd (#268). For multi-command sessions, export
  `IOS_RESEARCH_WORKSPACE=/abs/path/.ios-research` once — a single forgotten
  `--workspace` otherwise silently falls back to the cwd-relative workspace.
- **Operational hints**: pipeline commands (`fuzz`, `campaign`, `research`,
  `agent`) carry per-command `examples` (argv + expected envelope),
  `time_bounds` (`blocking` + which flags cap runtime, e.g.
  `--chunk`/`--duration`/`--max-cases`) and `next` (common follow-ups) in the
  schema (#268). Bound every long-running invocation explicitly.

## Agent commands

| Command | Purpose |
|---------|---------|
| `agent status` | Environment + workspace counts; `ready` flag |
| `agent inspect` | Full machine-readable CLI schema |
| `agent schema --out P` | Write the schema to a file |
| `agent experiment --target T` | Create a stamped experiment |
| `agent run --target T --max-cases N` | Bounded end-to-end pipeline |
| `agent analyze` | Analyze all crashes |
| `detect scan/lint/list-rules` | Defensive detection signatures (samples you supply) |
| `cve catalog/install-catalog/add/list/validate/remove` | Known-CVE patch-regression validation |

## Recommended workflow

```text
inspect environment   -> ios-research agent status --json
select target         -> ios-research target list --json
inspect corpus        -> ios-research corpus list --json
create experiment     -> ios-research experiment create --json
fuzz                  -> ios-research fuzz start --target T --json
detect crashes        -> ios-research crash list --json
deduplicate           -> (crashes are deduped by signature at record time)
minimize              -> ios-research crash minimize <id> --json [--max-executions N]
reproduce             -> ios-research crash reproduce <id> --json
analyze               -> ios-research analyze <id> --json
differential test     -> ios-research diff run --json
generate report       -> ios-research report create <id> --json
patch regression      -> ios-research cve validate --json
sample triage         -> ios-research detect scan <file> --json
```

`agent run` performs fuzz → reproduce → minimize → analyze in one call for a
bounded number of cases.

## Safety (enforced)

Destructive operations (e.g. `research run` consuming large budgets) require an
explicit `--yes`; without it the operation is refused. Agents are **not** given
capabilities for exploit deployment, covert surveillance, persistence,
credential theft, or sandbox/TCC bypass — these are outside the framework's
boundary (`SECURITY.md`) and fail with exit code `5`.

## Operating rules for research agents (mandatory)

Several agents share one Mac and one repository. Each rule below exists
because breaking it already cost hours: the strategy of record is
[`research/plans/GO-FORWARD-STRATEGY.md`](research/plans/GO-FORWARD-STRATEGY.md).

**Workspace**
- Work only in your own worktree, `.worktrees/<name>`. Never edit, stash or
  switch branches in the main checkout; never use a bare `git stash` (the
  stash stack is shared). Branch collisions wiped uncommitted work in August.
- Worktrees have no venv of their own: run
  `PYTHONPATH=src ../../.venv/bin/python ...`. Without `PYTHONPATH=src` you
  silently import the main checkout's code.

**Processes and builds**
- Kill only processes you started, by PID. Never `pkill` by pattern: other
  agents' campaigns run the same harness binaries.
- Never run `tools/harness/build.sh` while a `run.py` campaign is running: it
  rewrites `tools/harness/build/<fw>_fuzzer`, the binary the campaign keeps
  launching. `tools/harness/jackalope.sh` is safe (it builds a private copy).

**Oracle**
- Every campaign starts with the detection canary (`run.py` runs it; exit 4
  means the oracle is blind or noisy). Stop and report on a failure under the
  default or `MALLOC_PROTECT_BEFORE` oracle. Never pass `--no-canary`.
- Don't use `MALLOC_STRICT_SIZE` on macOS 26.x: it crashes all four harnesses
  on valid input (CoreText on real fonts in `findCFBurstTrieList`; the
  canary's one small font seed passes, so the canary alone doesn't show it).
  See `docs/MAC-FUZZING.md`, Detection.

**Evidence**
- A finding is a file that crashes the standalone Guard Malloc harness 3 times
  out of 3 under the environment that found it. OS `.ips` reports, dead
  batches and Jackalope crashes are not findings.
- Jackalope teardown signature, ignore on sight: `parentProc: "Exited
  process"`, no `libgmalloc.dylib` in `usedImages`, `KERN_PROTECTION_FAILURE`
  with the fault address equal to the PC inside a framework's `__TEXT`, `?`
  frames. 23 such reports sent a whole scan after a bug that did not exist.
- One-hour rule: a signal with no 3/3 reproducing file after an hour of effort
  is recorded and dropped. Never build tooling to chase a signal that has not
  reproduced once.

**Disclosure** (this repository is public)
- Unreported findings, open leads, proofs of concept and Apple thread IDs live
  only in `research/findings/` (gitignored). Never `git add -f` there, and never
  describe them in tracked files, commit messages or PR text.

**Scope**
- Platform freeze: no new `src/ios_research` module unless a research lane
  needs it. New lane tooling goes under `tools/`, next to its lane.

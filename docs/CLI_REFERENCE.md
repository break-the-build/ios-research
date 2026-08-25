# CLI Reference

Auto-generated from the framework schema (`ios-research agent inspect`). Framework version `0.1.0`.

## Global flags

- `--json`
- `--verbose`
- `--quiet`
- `--workspace`
- `--config`
- `--yes`

## JSON envelope

Every command supports `--json` and returns:

```json
{ "ok": true, "command": "...", "data": {}, "messages": [], "error": null, "exit_code": 0 }
```

## Exit codes

- `0` — OK
- `1` — ERROR
- `2` — USAGE
- `3` — NOT_FOUND
- `4` — VALIDATION
- `5` — SAFETY
- `6` — INTERRUPTED
- `7` — STATE

## Commands


### `ios-research advisory`

Positional arguments:

- `subcommand` (required)

### `ios-research advisory import`

Positional arguments:

- `path` (required)

### `ios-research advisory list`

### `ios-research advisory match`

Positional arguments:

- `crash_id` (required)

### `ios-research advisory scan`

Options:

- `--experiment-id`
### `ios-research agent`

### `ios-research agent analyze`

### `ios-research agent experiment`

Options:

- `--target`
- `--seed`

### `ios-research agent inspect`

### `ios-research agent run`

Options:

- `--target`
- `--seed`
- `--max-cases`
- `--no-minimize`

### `ios-research agent schema`

Options:

- `--out`

### `ios-research agent status`

### `ios-research analysis`

### `ios-research analysis list`

### `ios-research analysis show`

Positional arguments:

- `analysis_id` (required)

### `ios-research analyze`

Positional arguments:

- `crash_id` (optional)

Options:

- `--batch` — analyze all crashes (default when no id is given)


### `ios-research campaign`

Positional arguments:

- `subcommand` (required)

### `ios-research campaign export`

Options:

- `--corpus`
- `--out`
- `--worker`
- `--campaign`

### `ios-research campaign import`

Options:

- `--from`
- `--corpus`
- `--dry-run`
- `--require-new-coverage`

### `ios-research campaign status`

Options:

- `--campaign`

### `ios-research beta`

Positional arguments:

- `subcommand` (required)

### `ios-research beta diff`

Options:

- `--release-a`
- `--release-b`

### `ios-research beta list`

### `ios-research beta show`

Positional arguments:

- `diff_id` (required)

### `ios-research beta tag`

Positional arguments:

- `diff_id` (required)

Options:

- `--corpus`
### `ios-research config`

### `ios-research config get`

Positional arguments:

- `key` (required) — dotted key, e.g. fuzz.workers

### `ios-research config hash`

### `ios-research config list`

### `ios-research config set`

Positional arguments:

- `key` (required)
- `value` (required) — JSON or scalar value

### `ios-research corpus`

### `ios-research corpus create`

Positional arguments:

- `name` (required)

Options:

- `--target`
- `--seed-default` — add a single valid base testcase

### `ios-research corpus dedupe`

Positional arguments:

- `corpus_id` (required)

### `ios-research corpus import`

Positional arguments:

- `corpus_id` (required)
- `path` (required)

### `ios-research corpus inspect`

Positional arguments:

- `corpus_id` (required)

### `ios-research corpus list`

### `ios-research corpus minimize`

Positional arguments:

- `corpus_id` (required)

Options:

- `--target`

### `ios-research crash`

### `ios-research crash classify`

Positional arguments:

- `crash_id` (required)

### `ios-research crash compare`

Positional arguments:

- `crash_id_a` (required)
- `crash_id_b` (required)

### `ios-research crash list`

### `ios-research crash minimize`

Positional arguments:

- `crash_id` (required)

### `ios-research crash reproduce`

Positional arguments:

- `crash_id` (required)

### `ios-research crash show`

Positional arguments:

- `crash_id` (required)


### `ios-research cve`

Positional arguments:

- `subcommand` (required)

### `ios-research cve add`

Positional arguments:

- `cve_id` (required)

Options:

- `--title`
- `--input-hex`
- `--input-file`
- `--vulnerable`
- `--fixed`
- `--reference`
- `--note`

### `ios-research cve catalog`

### `ios-research cve install-catalog`

### `ios-research cve list`

### `ios-research cve remove`

Positional arguments:

- `cve_id` (required)

### `ios-research cve validate`

Positional arguments:

- `cve_id` (optional)

### `ios-research detect`

Positional arguments:

- `subcommand` (required)

### `ios-research detect lint`

Options:

- `--rules`

### `ios-research detect list-rules`

Options:

- `--rules`

### `ios-research detect scan`

Positional arguments:

- `path` (required)

Options:

- `--rules`
### `ios-research device`

### `ios-research device list`

### `ios-research device show`

Positional arguments:

- `device_id` (required)

### `ios-research diff`

### `ios-research diff compare`

Positional arguments:

- `diff_id` (optional)

### `ios-research diff create`

Options:

- `--name`
- `--target-a`
- `--target-b`
- `--corpus`
- `--seed`

### `ios-research diff list`

### `ios-research diff report`

Positional arguments:

- `diff_id` (optional)

### `ios-research diff run`

Positional arguments:

- `diff_id` (optional)

### `ios-research doctor`


### `ios-research engine`

Positional arguments:

- `subcommand` (required)

### `ios-research engine import`

Positional arguments:

- `manifest` (required)

Options:

- `--experiment-id`

### `ios-research engine list`
### `ios-research experiment`

### `ios-research experiment create`

Options:

- `--target`
- `--device`
- `--seed`

### `ios-research experiment list`

### `ios-research experiment show`

Positional arguments:

- `experiment_id` (required)

### `ios-research fuzz`

### `ios-research fuzz pause`

Positional arguments:

- `session_id` (optional)

### `ios-research fuzz resume`

Positional arguments:

- `session_id` (optional)

Options:

- `--chunk`
- `--duration`

### `ios-research fuzz start`

Options:

- `--target`
- `--corpus`
- `--experiment`
- `--seed`
- `--max-cases`
- `--duration` — wall-clock budget in seconds
- `--workers`
- `--chunk` — cases to execute this invocation (for resumable runs)
- `--llm-proposals` — JSONL proposal file for LLM-in-the-loop mutation (#71); requires --llm-budget
- `--llm-budget` — max proposals consumed per campaign
- `--focus-symbol` — directed scheduling toward this symbol (#73); requires a target with a callgraph() hook

### `ios-research fuzz stats`

Positional arguments:

- `session_id` (optional)

### `ios-research fuzz status`

Positional arguments:

- `session_id` (optional)

### `ios-research fuzz stop`

Positional arguments:

- `session_id` (optional)

### `ios-research info`

### `ios-research init`

Options:

- `--force` — re-initialize even if a workspace exists

### `ios-research findings`

### `ios-research findings adjudicate`

Positional arguments:

- `finding_id` (optional)

### `ios-research findings confirm`

Positional arguments:

- `finding_id` (required)

Options:

- `--reason`

### `ios-research findings dismiss`

Positional arguments:

- `finding_id` (required)

Options:

- `--reason`

### `ios-research findings import`

Options:

- `--sarif` (required) — path to the SARIF JSON file
- `--tool` — override tool name for all imported findings

### `ios-research findings list`

Options:

- `--status`
- `--cwe`

### `ios-research findings objectives`

### `ios-research findings show`

Positional arguments:

- `finding_id` (required)

### `ios-research harness`

### `ios-research harness accept`

Positional arguments:

- `candidate_id` (required)

### `ios-research harness generate`

Options:

- `--provider` — harness proposal provider
- `--proposals-path` — JSON file of proposals (provider 'file')
- `--max-candidates` — max candidates
- `--smoke` — execute validated candidates once (opt-in)
- `--target` (required)

### `ios-research harness list`

Options:

- `--status`
- `--target`

### `ios-research harness reject`

Positional arguments:

- `candidate_id` (required)

Options:

- `--reason`

### `ios-research harness show`

Positional arguments:

- `candidate_id` (required)

<<<<<<< HEAD
### `ios-research kernel`

### `ios-research kernel msg-build`

Options:

- `--bits`
- `--remote`
- `--local`
- `--voucher`
- `--id` — id
- `--port` — port right name (repeatable)
- `--ool-size` — OOL region size (repeatable)
- `--payload` — hex payload bytes
- `--out` (required) — write the packed message here

### `ios-research kernel msg-unpack`

Positional arguments:

- `input` (required)

### `ios-research kernel surface`

=======

### `ios-research matrix`

Positional arguments:

- `subcommand` (required)

### `ios-research matrix create`

Options:

- `--target`
- `--input`
- `--trials`
- `--seed`
- `--cells`

### `ios-research matrix list`

### `ios-research matrix run`

Positional arguments:

- `matrix_id` (required)

### `ios-research matrix show`

Positional arguments:

- `matrix_id` (required)

### `ios-research nday`

Positional arguments:

- `subcommand` (required)

### `ios-research nday campaign`

Positional arguments:

- `nday_id` (required)

Options:

- `--reachable`

### `ios-research nday diff`

Options:

- `--name`
- `--symbols-a`
- `--symbols-b`

### `ios-research nday list`

### `ios-research nday prioritize`

Positional arguments:

- `nday_id` (required)

Options:

- `--reachable`

### `ios-research nday show`

Positional arguments:

- `nday_id` (required)

### `ios-research net`

Positional arguments:

- `subcommand` (required)

### `ios-research net deliver`

Options:

- `--target`
- `--input`
- `--schedule`

### `ios-research net replay`

Options:

- `--target`
- `--input`
- `--schedule`
- `--capture`

### `ios-research oracle`

Positional arguments:

- `subcommand` (required)

### `ios-research oracle list`

### `ios-research oracle run`

Positional arguments:

- `spec` (required)

Options:

- `--corpus`

### `ios-research oracle show`

Positional arguments:

- `run_id` (required)
>>>>>>> origin/main
### `ios-research races`

Positional arguments:

- `subcommand` (required)

### `ios-research races import`

Options:

- `--report` (required) — path to a saved TSan report text file
- `--target` — target id the report came from
- `--input-sha` — sha256 of the triggering input, if known

### `ios-research races list`

Options:

- `--kind` — filter by race kind (e.g. 'data race')

### `ios-research races show`

Positional arguments:

- `race_id` (required)

### `ios-research report`

### `ios-research report bounty-export`

Positional arguments:

- `report_id` (required)

Options:

- `--metadata` — local JSON researcher metadata/attestations
- `--out` — output directory for the redacted evidence pack and local artifacts

### `ios-research report bounty-validate`

Positional arguments:

- `report_id` (required)

Options:

- `--metadata` — local JSON researcher metadata/attestations

### `ios-research report create`

Positional arguments:

- `crash_id` (required)

### `ios-research report export`

Positional arguments:

- `report_id` (required)

Options:

- `--format`
- `--out`

### `ios-research report list`

### `ios-research report show`

Positional arguments:

- `report_id` (required)

### `ios-research report validate`

Positional arguments:

- `report_id` (required)

### `ios-research research`

### `ios-research research create`

Options:

- `--name`
- `--target`
- `--seed`
- `--max-cases`
- `--max-runtime`
- `--max-testcases`

### `ios-research research pause`

Positional arguments:

- `research_id` (optional)

### `ios-research research resume`

Positional arguments:

- `research_id` (optional)

Options:

- `--max-stages`

### `ios-research research run`

Positional arguments:

- `research_id` (optional)

Options:

- `--max-stages` — run only N stages (resumable)

### `ios-research research status`

Positional arguments:

- `research_id` (optional)

### `ios-research research summarize`

Positional arguments:

- `research_id` (optional)

### `ios-research spoints`

### `ios-research spoints list`

### `ios-research spoints points`

Positional arguments:

- `report_id` (required)
- `crash_id` (required)

### `ios-research spoints run`

Options:

- `--experiment`
- `--limit` — limit

### `ios-research spoints show`

Positional arguments:

- `report_id` (required)


### `ios-research staticscan`

Static-analysis scout: surface census, parser fingerprinting, call-graph
export (#223).

Positional arguments:

- `subcommand` (required)

### `ios-research staticscan locate`

Locate a framework binary (loose path or dyld shared cache).

Positional arguments:

- `framework` (required) — bare framework name, e.g. `AudioToolbox`

### `ios-research staticscan scan`

Census a Mach-O or dyld shared cache: symbols, linked libraries, constant
strings.

Positional arguments:

- `path` (required)

Options:

- `--min-len` — minimum string length (default 4)

### `ios-research staticscan fingerprint`

Identify parser families by format constants (magic bytes, chunk names,
section tags) with per-token hit evidence.

Positional arguments:

- `path` (required)

### `ios-research staticscan dict`

Emit an evidence-backed libFuzzer dictionary from the matched constants.

Positional arguments:

- `path` (required)

Options:

- `--families` — comma-separated family filter (default: all matched)
- `--out` — write dictionary to a file instead of stdout

### `ios-research staticscan callgraph`

Normalize a Ghidra headless export (`tools/staticscan/ghidra_export.py`)
into the directed-fuzzing call-graph document.

Positional arguments:

- `export_json` (required)

Options:

- `--out` — write the call-graph document to a file
- `--focus` — list parser focus functions (functions referencing format
  constants)

### `ios-research surface`

Positional arguments:

- `subcommand` (required)

### `ios-research surface ingest`

Positional arguments:

- `path` (required)

### `ios-research surface list`

### `ios-research surface plan`

Options:

- `--inventory`
- `--previous-plan`
- `--novelty-yield`
- `--saturation-penalty`

### `ios-research surface show`

Positional arguments:

- `plan_id` (required)


### `ios-research supply`

Positional arguments:

- `subcommand` (required)

### `ios-research supply audit`

Options:

- `--requirements` — path to requirements.txt-style text (required)

### `ios-research supply list`

### `ios-research supply scan`

Positional arguments:

- `path` (required)

### `ios-research supply show`

Positional arguments:

- `record_id` (required)

### `ios-research supply verify`

Options:

- `--lockfile` — path to the lockfile JSON (required)
- `--root` — root directory lock paths resolve against

### `ios-research target`

### `ios-research target audio`

### `ios-research target audio inspect`

Positional arguments:

- `format` (required) — wav|mp3|aac|alac or a full id

### `ios-research target audio list`

### `ios-research target list`

### `ios-research target show`

Positional arguments:

- `target_id` (required)


### `ios-research targetflags`

Positional arguments:

- `subcommand` (required)

### `ios-research targetflags list`

### `ios-research targetflags show`

Positional arguments:

- `flag_id` (required)
### `ios-research version`

### `ios-research xcode`

Positional arguments:

- `subcommand` (required)

### `ios-research xcode plan`

Positional arguments:

- `plan_subcommand` (required)

### `ios-research xcode plan import`

Positional arguments:

- `path` (required)

### `ios-research xcode plan list`

### `ios-research xcode plan show`

Positional arguments:

- `plan_id` (required)

### `ios-research xcode repro`

Positional arguments:

- `record_id` (required)

Options:

- `--plan`
- `--failure-index`
- `--project`
- `--xcode-workspace`

### `ios-research xcode test`

Positional arguments:

- `plan_id` (required)

Options:

- `--project`
- `--xcode-workspace`
- `--destination`
- `--only-testing`
- `--sanitizer`
- `--result-bundle-path`
- `--dry-run`
- `--timeout`

### `ios-research xcode xcresult`

Positional arguments:

- `xcr_subcommand` (required)

### `ios-research xcode xcresult list`

### `ios-research xcode xcresult parse`

Positional arguments:

- `path` (required)

### `ios-research xcode xcresult show`

Positional arguments:

- `record_id` (required)

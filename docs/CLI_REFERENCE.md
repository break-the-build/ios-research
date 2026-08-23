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

### `ios-research version`

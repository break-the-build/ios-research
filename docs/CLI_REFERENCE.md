# CLI Reference

Auto-generated from the framework schema (`ios-research agent inspect`); framework version `0.1.0`. Regenerate with `python tools/gen_cli_reference.py` after changing CLI registration.

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

- `subcommand`

### `ios-research advisory import`

Positional arguments:

- `path` — JSON file with an 'advisories' array

### `ios-research advisory list`


### `ios-research advisory match`

Positional arguments:

- `crash_id`

### `ios-research advisory scan`

Options:

- `--experiment-id`

### `ios-research agent`

Positional arguments:

- `subcommand`

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
- `--distill-corpus` — after triage completes, distill the pipeline corpus to one representative per distinct behavior; runs between sessions, never mid-advance (deterministic)
- `--workers` — thread pool width for post-fuzz crash triage (default 1 = serial)

### `ios-research agent schema`

Options:

- `--out`

### `ios-research agent status`


### `ios-research analysis`

Positional arguments:

- `subcommand`

### `ios-research analysis list`


### `ios-research analysis show`

Positional arguments:

- `analysis_id`

### `ios-research analyze`

Positional arguments:

- `crash_id` (optional)

Options:

- `--batch` — analyze all crashes (default when no id is given)

### `ios-research benchmark`

Positional arguments:

- `subcommand`

### `ios-research benchmark native-profile`

Options:

- `--target` (required) — built mac:<framework> target to profile
- `--max-cases` — bounded seed executions (default: 10)
- `--acknowledge-authorized-use` — confirm authorization to execute the local native harness

### `ios-research benchmark profile`

Options:

- `--target` — mock target to profile (default: mock:parser)
- `--max-cases` — bounded fuzz cases (default: 1000)
- `--seed` — deterministic mutation seed (default: 0)

### `ios-research beta`

Positional arguments:

- `subcommand`

### `ios-research beta diff`

Options:

- `--release-a` (required)
- `--release-b` (required)

### `ios-research beta list`


### `ios-research beta show`

Positional arguments:

- `diff_id`

### `ios-research beta tag`

Positional arguments:

- `diff_id`

Options:

- `--corpus` (required)

### `ios-research campaign`

Positional arguments:

- `subcommand`

### `ios-research campaign export`

Options:

- `--corpus` (required)
- `--out` (required)
- `--worker` (required)
- `--campaign`

### `ios-research campaign import`

Options:

- `--from` (required)
- `--corpus` (required)
- `--dry-run`
- `--require-new-coverage` — skip inputs that add no new coverage feature

### `ios-research campaign status`

Options:

- `--campaign`

### `ios-research config`

Positional arguments:

- `subcommand`

### `ios-research config get`

Positional arguments:

- `key` — dotted key, e.g. fuzz.workers

### `ios-research config hash`


### `ios-research config list`


### `ios-research config set`

Positional arguments:

- `key`
- `value` — JSON or scalar value

### `ios-research corpus`

Positional arguments:

- `subcommand`

### `ios-research corpus create`

Positional arguments:

- `name`

Options:

- `--target`
- `--seed-default` — add a single valid base testcase

### `ios-research corpus dedupe`

Positional arguments:

- `corpus_id`

### `ios-research corpus import`

Positional arguments:

- `corpus_id`
- `path`

### `ios-research corpus inspect`

Positional arguments:

- `corpus_id`

### `ios-research corpus list`


### `ios-research corpus minimize`

Positional arguments:

- `corpus_id`

Options:

- `--target`

### `ios-research crash`

Positional arguments:

- `subcommand`

### `ios-research crash classify`

Positional arguments:

- `crash_id`

### `ios-research crash compare`

Positional arguments:

- `crash_id_a`
- `crash_id_b`

### `ios-research crash list`

Options:

- `--new-only` — only records not yet worked (status == 'new'). No pipeline stage transitions status today, so this currently matches every record; the flag exists so agents can rely on the contract once status transitions land (#264)

### `ios-research crash minimize`

Positional arguments:

- `crash_id`

Options:

- `--max-executions` — bound total target executions during minimization

### `ios-research crash reproduce`

Positional arguments:

- `crash_id`

### `ios-research crash show`

Positional arguments:

- `crash_id`

### `ios-research cve`

Positional arguments:

- `subcommand`

### `ios-research cve add`

Positional arguments:

- `cve_id`

Options:

- `--title` (required)
- `--input-hex` — hex-encoded input (mutually exclusive with --input-file)
- `--input-file` — read the input from this file instead
- `--vulnerable` — comma-separated targets that must crash
- `--fixed` — comma-separated targets that must stay clean
- `--reference`
- `--note`

### `ios-research cve catalog`


### `ios-research cve install-catalog`


### `ios-research cve list`


### `ios-research cve remove`

Positional arguments:

- `cve_id`

### `ios-research cve validate`

Positional arguments:

- `cve_id` (optional)

### `ios-research detect`

Positional arguments:

- `subcommand`

### `ios-research detect lint`

Options:

- `--rules` — rules JSON (default: built-in signatures)

### `ios-research detect list-rules`

Options:

- `--rules`

### `ios-research detect scan`

Positional arguments:

- `path`

Options:

- `--rules` — rules JSON (default: built-in signatures)

### `ios-research device`

Positional arguments:

- `subcommand`

### `ios-research device list`


### `ios-research device show`

Positional arguments:

- `device_id`

### `ios-research diff`

Positional arguments:

- `subcommand`

### `ios-research diff compare`

Positional arguments:

- `diff_id` (optional)

### `ios-research diff create`

Options:

- `--name`
- `--target-a` (required)
- `--target-b` (required)
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

- `subcommand`

### `ios-research engine import`

Positional arguments:

- `manifest` — path to the import manifest JSON

Options:

- `--experiment-id` — attach imported findings to an existing experiment

### `ios-research engine list`


### `ios-research evidence`

Positional arguments:

- `subcommand`

### `ios-research evidence import`

Positional arguments:

- `crash_id`
- `path`

Options:

- `--kind` (required) — crash-log | sysdiagnose | video | screenshot | syslog | other
- `--device-id`
- `--build`
- `--process`
- `--captured-at` — researcher-supplied ISO-8601 capture time
- `--redaction-ack` — confirm review/redaction responsibility for video/screenshot artifacts
- `--notes`

### `ios-research evidence list`

Positional arguments:

- `crash_id`

### `ios-research evidence verify`

Positional arguments:

- `item_id`

### `ios-research experiment`

Positional arguments:

- `subcommand`

### `ios-research experiment create`

Options:

- `--target`
- `--device`
- `--seed`
- `--delivery` — researcher-declared input-delivery channel (reporting provenance, #106)

### `ios-research experiment list`


### `ios-research experiment show`

Positional arguments:

- `experiment_id`

### `ios-research findings`

Positional arguments:

- `subcommand`

### `ios-research findings adjudicate`

Positional arguments:

- `finding_id` (optional)

### `ios-research findings confirm`

Positional arguments:

- `finding_id`

Options:

- `--reason`

### `ios-research findings dismiss`

Positional arguments:

- `finding_id`

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

- `finding_id`

### `ios-research fuzz`

Positional arguments:

- `subcommand`

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
- `--delivery` — researcher-declared input-delivery channel (reporting provenance, #106)
- `--duration` — wall-clock budget in seconds
- `--workers`
- `--focus-symbols` — comma-separated focus symbols rotated every fuzz.focus_phase_len cases (#205); overrides --focus-symbol when given
- `--adapt-strategies` — online strategy reweighting from per-strategy novel-feature yield every fuzz.strategy_adapt_every cases (#203)
- `--skip-duplicates` — never execute the same input twice in a session (#204); duplicates are counted as skipped_duplicate
- `--window` — generation window: cases produced before execution fans out (>=1; default fuzz.window)
- `--chunk` — cases to execute this invocation (for resumable runs)
- `--dictionary` — path to a token dictionary (constraint-guided mutation, #30)
- `--value-profile` — record value-profile guidance in campaign metadata (#30)
- `--sanitizer-profile` — named sanitizer build profile recorded as provenance (#31)
- `--mutator-plugin` — path to a grammar-aware mutator plugin (#41)
- `--max-input-bytes` — skip mutated inputs larger than this many bytes (default 1048576; 0 disables the bound)
- `--llm-proposals` — JSONL proposal file for LLM-in-the-loop mutation (#71); requires --llm-budget
- `--llm-budget` — max proposals consumed per campaign
- `--focus-symbol` — directed scheduling toward this symbol (#73); requires a target with a callgraph() hook
- `--sched-perturb` — comma-separated scheduling-perturbation modes applied between cases (#70): yield,priority,affinity,random-delay

### `ios-research fuzz stats`

Positional arguments:

- `session_id` (optional)

### `ios-research fuzz status`

Positional arguments:

- `session_id` (optional)

### `ios-research fuzz stop`

Positional arguments:

- `session_id` (optional)

### `ios-research harness`

Positional arguments:

- `subcommand`

### `ios-research harness accept`

Positional arguments:

- `candidate_id`

### `ios-research harness generate`

Options:

- `--target` (required)
- `--provider`
- `--proposals-path` — JSON file of proposals (provider 'file')
- `--max-candidates`
- `--smoke` — execute validated candidates once (opt-in)

### `ios-research harness list`

Options:

- `--status`
- `--target`

### `ios-research harness reject`

Positional arguments:

- `candidate_id`

Options:

- `--reason`

### `ios-research harness show`

Positional arguments:

- `candidate_id`

### `ios-research info`


### `ios-research init`

Options:

- `--force` — re-initialize even if a workspace exists

### `ios-research kernel`

Positional arguments:

- `subcommand`

### `ios-research kernel msg-build`

Options:

- `--bits`
- `--remote`
- `--local`
- `--voucher`
- `--id`
- `--port` — port right name (repeatable)
- `--ool-size` — OOL region size (repeatable)
- `--payload` — hex payload bytes
- `--out` (required) — write the packed message here

### `ios-research kernel msg-unpack`

Positional arguments:

- `input`

### `ios-research kernel surface`


### `ios-research lockdown`

Positional arguments:

- `subcommand`

### `ios-research lockdown create`

Options:

- `--name`
- `--target-standard` (required)
- `--target-lockdown` (required)
- `--build-standard` (required) — build id of the standard configuration
- `--build-lockdown` (required) — build id of the lockdown configuration
- `--corpus`
- `--real-device` — pair runs against a real enrolled device (opt-in; default is simulation fixtures)

### `ios-research lockdown list`


### `ios-research lockdown run`

Positional arguments:

- `pair_id` (optional)

Options:

- `--attest-lockdown-enabled` — researcher attestation that the lockdown configuration was enabled

### `ios-research lockdown show`

Positional arguments:

- `pair_id` (optional)

### `ios-research lockdown state`


### `ios-research matrix`

Positional arguments:

- `subcommand`

### `ios-research matrix create`

Options:

- `--target` (required)
- `--input` (required) — path to the input to confirm
- `--trials`
- `--seed`
- `--cells` (required) — JSON file with an array of cell specs (device_id, model, os_name, os_version, build)

### `ios-research matrix list`


### `ios-research matrix run`

Positional arguments:

- `matrix_id`

### `ios-research matrix show`

Positional arguments:

- `matrix_id`

### `ios-research nday`

Positional arguments:

- `subcommand`

### `ios-research nday campaign`

Positional arguments:

- `nday_id`

Options:

- `--reachable` (required)

### `ios-research nday diff`

Options:

- `--name` (required)
- `--symbols-a` (required)
- `--symbols-b` (required)

### `ios-research nday list`


### `ios-research nday prioritize`

Positional arguments:

- `nday_id`

Options:

- `--reachable` (required)

### `ios-research nday show`

Positional arguments:

- `nday_id`

### `ios-research net`

Positional arguments:

- `subcommand`

### `ios-research net deliver`

Options:

- `--target` (required) — transport target id (net:<inner-target>)
- `--input` (required)
- `--schedule`

### `ios-research net replay`

Options:

- `--target` (required)
- `--input` (required)
- `--schedule`
- `--capture` (required) — JSON file with a saved capture

### `ios-research oracle`

Positional arguments:

- `subcommand`

### `ios-research oracle list`


### `ios-research oracle mac`

Positional arguments:

- `mac_subcommand`

### `ios-research oracle run`

Positional arguments:

- `spec` — path to the oracle spec JSON

Options:

- `--corpus` — corpus id providing the base inputs

### `ios-research oracle show`

Positional arguments:

- `run_id`

### `ios-research proximity`

Positional arguments:

- `subcommand`

### `ios-research proximity list`


### `ios-research proximity smoke`

Positional arguments:

- `profile_id`

Options:

- `--enable` — explicitly opt in to this profile for this invocation
- `--max-cases`

### `ios-research races`

Positional arguments:

- `subcommand`

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

- `race_id`

### `ios-research report`

Positional arguments:

- `subcommand`

### `ios-research report bounty-export`

Positional arguments:

- `report_id`

Options:

- `--metadata` — optional local JSON metadata/attestations
- `--out` — output directory (default: report evidence directory)

### `ios-research report bounty-validate`

Positional arguments:

- `report_id`

Options:

- `--metadata` — optional local JSON metadata/attestations
- `--tccutil-output` — captured 'tccutil flag check' text file (#84); makes the TCC flag check binding

### `ios-research report coverage`

Positional arguments:

- `session_id` (optional)

Options:

- `--markdown`

### `ios-research report coverage-compare`

Positional arguments:

- `base_session_id`
- `head_session_id`

### `ios-research report create`

Positional arguments:

- `crash_id`

### `ios-research report export`

Positional arguments:

- `report_id`

Options:

- `--format`
- `--out`

### `ios-research report list`


### `ios-research report reachability`

Positional arguments:

- `session_id` (optional)

Options:

- `--inventory` (required) — JSON file with a list of statically reachable feature/function IDs

### `ios-research report show`

Positional arguments:

- `report_id`

### `ios-research report validate`

Positional arguments:

- `report_id`

### `ios-research research`

Positional arguments:

- `subcommand`

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

### `ios-research sequence`

Positional arguments:

- `subcommand`

### `ios-research sequence fuzz`

Options:

- `--adapter` (required) — path to a user-declared workflow adapter module
- `--cases`
- `--seed`
- `--max-length`

### `ios-research spoints`

Positional arguments:

- `subcommand`

### `ios-research spoints list`


### `ios-research spoints points`

Positional arguments:

- `report_id`
- `crash_id`

### `ios-research spoints run`

Options:

- `--experiment` — restrict to one experiment
- `--limit`

### `ios-research spoints show`

Positional arguments:

- `report_id`

### `ios-research srd`

Positional arguments:

- `subcommand`

### `ios-research srd collect`


### `ios-research srd run`

Positional arguments:

- `adapter`

Options:

- `--timeout` — override the adapter timeout in seconds
- `--note` — free-text researcher note stored with the run

### `ios-research srd status`


### `ios-research staticscan`

Positional arguments:

- `subcommand`

### `ios-research staticscan callgraph`

Positional arguments:

- `export_json`

Options:

- `--out`
- `--focus` — list parser focus functions (functions that reference format constants)

### `ios-research staticscan dict`

Positional arguments:

- `path`

Options:

- `--families` — comma-separated family filter (default: all matched)
- `--out` — write dictionary to a file instead of stdout

### `ios-research staticscan diff`

Positional arguments:

- `old_path`
- `new_path`

### `ios-research staticscan extract`

Positional arguments:

- `framework` — bare framework name, e.g. CoreText

Options:

- `--out` — output directory (default: <workspace>/artifacts/dsc)

### `ios-research staticscan fingerprint`

Positional arguments:

- `path`

### `ios-research staticscan locate`

Positional arguments:

- `framework` — bare framework name, e.g. AudioToolbox

### `ios-research staticscan scan`

Positional arguments:

- `path`

Options:

- `--min-len` — minimum string length (default 4)

### `ios-research suite`

Positional arguments:

- `subcommand`

### `ios-research suite benchmark`

Positional arguments:

- `name`

Options:

- `--target` (required)
- `--cases`
- `--seed`
- `--suite-version`

### `ios-research suite example`

Options:

- `--out` (required)

### `ios-research suite install`

Positional arguments:

- `directory`

### `ios-research suite list`


### `ios-research suite remove`

Positional arguments:

- `name`

Options:

- `--version` (required)

### `ios-research suite show`

Positional arguments:

- `name`

Options:

- `--version`

### `ios-research suite validate`

Positional arguments:

- `directory`

### `ios-research supply`

Positional arguments:

- `subcommand`

### `ios-research supply audit`

Options:

- `--requirements` (required) — path to requirements.txt-style text

### `ios-research supply list`


### `ios-research supply scan`

Positional arguments:

- `path` — directory of *.py files to scan

### `ios-research supply show`

Positional arguments:

- `record_id`

### `ios-research supply verify`

Options:

- `--lockfile` (required) — path to the lockfile JSON
- `--root` — root directory lock paths resolve against

### `ios-research surface`

Positional arguments:

- `subcommand`

### `ios-research surface ingest`

Positional arguments:

- `path`

### `ios-research surface list`


### `ios-research surface plan`

Options:

- `--inventory` (required) — surface-inventory id from 'surface ingest'
- `--previous-plan` — down-rank surfaces covered by an earlier plan
- `--novelty-yield` — explicit novel ratio override [0..1] (default: latest advisory scan or 0.5)
- `--saturation-penalty`

### `ios-research surface show`

Positional arguments:

- `plan_id`

### `ios-research target`

Positional arguments:

- `subcommand`

### `ios-research target audio`

Positional arguments:

- `audio_action`

### `ios-research target bluetooth`

Positional arguments:

- `bluetooth_action`

### `ios-research target build`

Positional arguments:

- `manifest` — path to target-manifest.json

Options:

- `--timeout-s` — build budget in seconds (default 300)

### `ios-research target continuity`

Positional arguments:

- `continuity_action`

### `ios-research target docimp`

Positional arguments:

- `docimp_action`

### `ios-research target fsclient`

Positional arguments:

- `fsclient_action`

### `ios-research target geo`

Positional arguments:

- `geo_action`

### `ios-research target init`

Options:

- `--language` (required) — harness language for the template
- `--dest` (required) — fresh project directory to populate
- `--name` — target name (default: --dest basename)
- `--acknowledge-authorized-use` — write authorization.ack=true; building and running the target executes user-declared local code on your own machine (see SECURITY.md)

### `ios-research target ipc`

Positional arguments:

- `ipc_action`

### `ios-research target list`


### `ios-research target lockeddevice`

Positional arguments:

- `lockeddevice_action`

### `ios-research target messaging`

Positional arguments:

- `messaging_action`

### `ios-research target netip`

Positional arguments:

- `netip_action`

### `ios-research target nfc`

Positional arguments:

- `nfc_action`

### `ios-research target pq3`

Positional arguments:

- `pq3_action`

### `ios-research target proxapp`

Positional arguments:

- `proxapp_action`

### `ios-research target register`

Positional arguments:

- `manifest` — path to target-manifest.json

### `ios-research target show`

Positional arguments:

- `target_id`

### `ios-research target signeddoc`

Positional arguments:

- `signeddoc_action`

### `ios-research target validate`

Positional arguments:

- `manifest` — path to target-manifest.json

Options:

- `--build-timeout-s` — build budget in seconds (default 300)

### `ios-research target voiceassist`

Positional arguments:

- `voiceassist_action`

### `ios-research target wifi`

Positional arguments:

- `wifi_action`

### `ios-research target wifiaware`

Positional arguments:

- `wifiaware_action`

### `ios-research target xpc`

Positional arguments:

- `xpc_action`

### `ios-research targetflags`

Positional arguments:

- `subcommand`

### `ios-research targetflags list`


### `ios-research targetflags show`

Positional arguments:

- `flag_id`

### `ios-research version`


### `ios-research xcode`

Positional arguments:

- `subcommand`

### `ios-research xcode import-plan`

Positional arguments:

- `path`

### `ios-research xcode parse-xcresult`

Positional arguments:

- `path`

### `ios-research xcode plan`

Positional arguments:

- `plan_subcommand`

### `ios-research xcode repro`

Positional arguments:

- `record_id`

Options:

- `--plan` (required)
- `--failure-index`
- `--project`
- `--xcode-workspace`

### `ios-research xcode repro-cmd`

Positional arguments:

- `record_id` (optional)

Options:

- `--plan` (required)
- `--failure-index`
- `--project`
- `--xcode-workspace`
- `--input` — minimized fuzz input path to map instead of a recorded failure
- `--action` — action sequence step (repeatable, with --input)
- `--test` — explicit -only-testing identifier override
- `--sanitizer`

### `ios-research xcode run-tests`

Positional arguments:

- `plan_id`

Options:

- `--project`
- `--xcode-workspace`
- `--destination`
- `--only-testing`
- `--sanitizer` — address|thread|undefined-behavior|main-thread-checker|guard-malloc|zombies|code-coverage (repeatable)
- `--result-bundle-path`
- `--dry-run` — print the command without executing (construction-only is the default)
- `--execute` — actually run xcodebuild (opt-in; requires --yes)
- `--timeout`

### `ios-research xcode test`

Positional arguments:

- `plan_id`

Options:

- `--project`
- `--xcode-workspace`
- `--destination`
- `--only-testing`
- `--sanitizer` — address|thread|undefined-behavior|main-thread-checker|guard-malloc|zombies|code-coverage (repeatable)
- `--result-bundle-path`
- `--dry-run` — print the command without executing (construction-only is the default)
- `--execute` — actually run xcodebuild (opt-in; requires --yes)
- `--timeout`

### `ios-research xcode xcresult`

Positional arguments:

- `xcr_subcommand`

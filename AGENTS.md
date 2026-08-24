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

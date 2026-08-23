# Apple Security Research Device Backend (#40)

The `srd:device` target supports **Apple Security Research Device (SRD)
program participants** behind the standard target interface. It is strictly
opt-in and fail-closed: it runs only against an explicitly configured, approved
SRD, and no code path requests, assumes, or obtains SRD access.

## Configuration (required)

Pass a dict to `SRDTarget(config=...)` or point `IOS_RESEARCH_SRD_CONFIG` at a
JSON file containing:

```json
{"approved": true, "device_id": "...", "model": "...",
 "build": "...", "authorized_user": "..."}
```

Any missing/invalid field keeps the target unavailable with an actionable
blocker; `execute()` then returns `ABNORMAL` — never a fabricated crash.

## What it does

- Records what you supply/observe: input SHA-256s, lifecycle events
  (`prepare`/`run`/`cleanup`), model/build/user/tool versions.
- `register_command_hook(name, fn)` stores *local* command hooks; they run only
  when you explicitly call `run_hook(name)` (output digest recorded).
- `collect_artifact(name, data)` hashes your bytes into the workspace
  `ArtifactStore`.

No exploit, bypass, credential, persistence, or privilege functionality exists
here — see `SECURITY.md`.

## Evidence separation

Every `describe()` / `provenance()` dict carries `"evidence_class": "srd"`, so
SRD evidence stays separate from retail-device (`ios-device:*`) evidence.

## CI

`srd:fake` is a deterministic mock backend (`kind: srd-fake`) covering the same
interface without hardware:

```bash
ios-research srd status                      # availability + missing fields
echo -n hi > /tmp/in.bin
ios-research srd fake-run --input-file /tmp/in.bin   # result + provenance
```

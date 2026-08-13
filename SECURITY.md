# Security & Safety Boundary

`ios-research` is a framework for **authorized** iOS security research. It is
built for defensive research workflows: fuzzing controlled targets, discovering
and reproducing crashes, triaging and minimizing them, analyzing memory-safety
issues, differential testing, and producing responsible-disclosure reports.

## Allowed capabilities

- Fuzzing and crash discovery against mock or explicitly authorized targets
- Crash reproduction, deduplication, and minimization
- Memory-safety analysis and safe exploitability *indicators*
- Differential testing across versions/configurations
- Research-device instrumentation (behind the same target interface)
- Responsible vulnerability reporting

## Forbidden capabilities (never implemented)

- Covert surveillance; camera or microphone activation
- Permission / TCC bypass; sandbox escape
- Persistence; credential theft; spyware; operational malware
- Weaponized exploit chains; exploit deployment against third-party devices
- Shellcode or ROP-chain generation

These boundaries are declared and enforced in
[`src/ios_research/safety.py`](src/ios_research/safety.py). Requests that cross
the boundary fail with exit code `5` (`SAFETY`).

## Operational safety

- Destructive operations require explicit confirmation (`--yes`); agents cannot
  perform them silently.
- Logs redact common secret-bearing keys (tokens, passwords, credentials).
- All shipped targets are **mock** targets safe to run in CI.

## Reporting

Use this framework only against systems and targets you are authorized to test.
Reports it generates are intended for responsible disclosure to the affected
vendor (e.g. Apple Product Security).

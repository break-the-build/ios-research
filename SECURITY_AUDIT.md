# Security & Reliability Audit

Audit performed in phase 10 against the whole repository. Scope follows
`docs/PROMPT-10-audit-hardening.md`. Issues found were **fixed**, not merely
documented.

## Method

- Full test suite with branch coverage (`pytest --cov`).
- CLI verification of every command from the RUN-ALL final-verification list,
  each with `--json`.
- Manual review of determinism, resumability, artifact integrity, error
  handling, and the safety boundary.

## Findings and remediation

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | Medium | Fuzz base set was recomputed each `advance()`, so corpus growth mid-run made resumed runs diverge from single runs. | **Fixed** — base set is snapshotted at session creation (`FuzzSession.base_shas`); resume equivalence is now test-verified. |
| 2 | Medium | Minimized crash inputs were not content-addressed, so report evidence referencing `minimized_sha256` failed validation. | **Fixed** — `CrashStore.write_minimized` also stores into the content-addressed artifact store. |
| 3 | Low | Rebuilding the CLI parser re-registered the `target audio` subcommand, raising "conflicting subparser". | **Fixed** — installer registration is idempotent. |

## Controls verified

- **Determinism**: fuzzing, differential runs, and full research runs are
  reproducible across fresh workspaces (dedicated tests).
- **Resumability**: interrupted fuzz sessions and research runs resume to a
  state identical to an uninterrupted run.
- **Artifact integrity**: JSON is written atomically (`os.replace`); inputs are
  content-addressed by SHA-256 and de-duplicated.
- **Crash deduplication**: crashes dedupe by diagnostic signature; repeats
  increment a counter rather than creating duplicates.
- **Unstable JSON**: every command emits the same envelope; the schema is
  committed and regenerated deterministically.
- **Destructive operations**: `research run`/`resume` refuse to proceed without
  `--yes` (exit code 6).
- **Secret/log hygiene**: `logging_util.redact` masks common secret keys
  (tokens, passwords, credentials) recursively; verified by test.
- **Experiment isolation**: all state is scoped to a workspace; tests run in
  isolated temp workspaces with a frozen clock.

## Safety boundary

`safety.py` enumerates forbidden capabilities (surveillance, camera/mic
activation, permission/TCC bypass, sandbox escape, persistence, credential
theft, spyware, weaponized exploit chains, exploit deployment, shellcode/ROP
generation). Report generation additionally scans for and rejects weaponized
content markers, and rejects exploitability claims that exceed the stored
analysis. No exploit-generation or covert-surveillance capability exists in the
codebase.

## Residual limitations

- All targets are **mock** targets; diagnostics are synthetic (deterministic)
  rather than captured from real hardware.
- "Workers" is recorded metadata; the reference engine executes sequentially to
  guarantee determinism.
- Storage accounting is best-effort (directory walk) and checked before the
  fuzz stage of a research run.

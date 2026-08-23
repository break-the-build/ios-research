# Apple Security Bounty Readiness

`ios-research` can check whether a local report has the evidence normally
needed for a responsible-disclosure draft and export a deterministic, redacted
evidence-reference pack:

```bash
ios-research report bounty-validate <report-id> --metadata researcher.json
ios-research report bounty-export <report-id> --metadata researcher.json
```

The optional metadata file is a local JSON object. It may include a `contact`
and `attestations.authorized_testing: true`. Credential-like fields, including
`token`, `authorization`, and `api_key`, are redacted recursively in exported
packs.

The checklist verifies report validity, retained minimized input and diagnostics,
reproduction, affected component/version, reproduction steps, and the supplied
authorization/contact attestations. A failed check means the evidence is
incomplete; it does **not** determine Apple Security Bounty eligibility,
severity, or reward.

## Target Flag awareness (#58)

`report bounty-validate` also maps findings to Apple's public **Target Flag**
taxonomy. `analyze` proposes *candidate* flags from stored evidence
(hypotheses only — never assertions of achievement), and researcher-declared
claims (`--metadata` JSON with `"target_flags": ["<flag-id>", ...]`) are checked
against the flag's required evidence elements:

```bash
ios-research targetflags list                 # local taxonomy + content hash
ios-research report bounty-validate <id> \
  --metadata researcher.json                  # includes per-flag checklists
```

An optional workspace override at `.ios-research/config/target-flags.json`
(`{"version": int, "flags": [...]}`) lets deployments track Apple's published
taxonomy without code changes; the effective taxonomy version and SHA-256 are
recorded in validation results and exported packs. This remains local-only:
it never interacts with Apple systems or actual Target Flag infrastructure.

## Target Flag capture detection (#84)

`analyze` additionally runs a structural check of stored diagnostics against
Apple's published **Commpage Target Flag** patterns (register control /
arbitrary read-write / code execution, userspace or kernel). When a pattern
matches — e.g. a faulting address that also appears live in a general-purpose
register on an `EXC_BAD_ACCESS` — the analysis records a
`target_flag_capture` block (primitive, space, bit width, confidence,
basis). NULL-page faults are never classified as captures.

Higher-fidelity detection uses the boot-random commpage contents captured on
the research device during the PoC run. Pass them via researcher metadata:

```json
{"commpage_values": {"value": "0x…", "address": "0x…",
                     "kern_value": "0x…", "kern_address": "0x…"}}
```

For **TCC Target Flag** demonstrations (macOS), supply the captured output of
Apple's own verification command to make the readiness check binding:

```bash
ios-research report bounty-validate <report-id> \
  --metadata researcher.json --tccutil-output tcc-check.txt
```

`tccutil flag check` reporting `modified` satisfies the check; reporting no
modification fails it explicitly. Detection results appear in
`bounty-validate` under `target_flags.capture` / `target_flags.tccutil`, are
usable as a `target_flag_capture` evidence element by override taxonomies,
and are exported in evidence packs. All parsing is local: the framework never
modifies TCC state, fabricates register data, or generates exploit material.
The taxonomy also gained the published PCC reward tiers (v2).

`bounty-export` creates a deterministic local directory containing
`manifest.json` and hash-verified copies of the retained original/minimized
inputs, crash record, and diagnostics. Only fixed workspace-relative paths are
accepted; missing files, hash mismatches, symlinks, and path escapes fail the
export. No data is transmitted. The command does not access Apple accounts, security
systems, Target Flags, privileged device capabilities, or generate exploits or
payloads. The exported pack contains local artifact references and hashes, not
raw exploit material.

## Mitigation-generation provenance (#87)

Since the 2025 Memory Integrity Enforcement devices, exploitability evidence
does not automatically transfer between mitigation generations. Matrix
reproduction results (#37) therefore record a per-cell
`mitigation_profile` (`mie-emte` / `pre-mie` / `unknown`), derived only from
the declared model/OS strings via the optional workspace table
`.ios-research/config/mitigation-models.json`:

```json
{"mie-emte": ["iPhone17,*"], "pre-mie": ["iPhone14,*", "iPhone15,*"]}
```

Unmatched devices record `unknown` (fail-closed; the framework ships no
authoritative hardware-identifier data). When reproducing cells or the
researcher-supplied `matrix_evidence` span multiple generations,
`bounty-validate` reports a **non-binding warning** — readiness is unaffected,
and no new device capabilities are introduced.

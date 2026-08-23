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

`bounty-export` creates a deterministic local directory containing
`manifest.json` and hash-verified copies of the retained original/minimized
inputs, crash record, and diagnostics. Only fixed workspace-relative paths are
accepted; missing files, hash mismatches, symlinks, and path escapes fail the
export. No data is transmitted. The command does not access Apple accounts, security
systems, Target Flags, privileged device capabilities, or generate exploits or
payloads. The exported pack contains local artifact references and hashes, not
raw exploit material.

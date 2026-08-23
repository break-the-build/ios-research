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

No data is transmitted. The command does not access Apple accounts, security
systems, Target Flags, privileged device capabilities, or generate exploits or
payloads. The exported pack contains local artifact references and hashes, not
raw exploit material.

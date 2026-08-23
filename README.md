# ios-research

A deterministic, CLI-driven framework for **authorized** iOS security research,
designed for both human researchers and LLM agents (such as Claude Code).

It runs the full research pipeline — corpus management, fuzzing, crash discovery,
triage, minimization, root-cause and exploitability analysis, differential
testing, and responsible-disclosure reporting — against controlled **mock
targets** that run anywhere (no iOS hardware required).

> **Authorized research only.** This framework performs fuzzing, crash analysis,
> and reporting against mock or explicitly authorized targets. It contains no
> exploit-generation, persistence, surveillance, or sandbox/TCC-bypass
> capabilities. See [SECURITY.md](SECURITY.md).

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ios-research --help
```

## Quick start

```bash
ios-research init                                   # create a workspace
ios-research fuzz start --target mock:parser --max-cases 500
ios-research crash list
ios-research crash minimize <crash-id>
ios-research analyze <crash-id>
ios-research report create <crash-id>
```

Or run the whole pipeline end to end:

```bash
ios-research research create --target mock:parser --max-cases 500
ios-research research run --yes
ios-research research summarize
```

Every command supports `--json` for a stable, machine-readable envelope.

## Targets

| Target | Description |
|--------|-------------|
| `mock:parser` / `mock:parser-v2` | Deterministic record parser; v2 adds fixes + one regression for differential testing |
| `audio:{wav,mp3,aac,alac}` | Mock audio-format parsers sharing a defect model |
| `bluetooth:{btle-adv,l2cap,gatt}` | Mock Bluetooth frame parsers sharing a defect model (bytes-only; no radio access) |
| `mac:{imageio,audiotoolbox,coregraphics}` | **Real** macOS in-process libFuzzer/ASan targets (`mock = False`); opt-in, require a built harness — see [docs/MAC-FUZZING.md](docs/MAC-FUZZING.md) |
| `ios-device:{file,imageio,audiotoolbox,coregraphics}` | **Real** black-box on-device targets (`mock = False`); stage an input to a USB-attached, *authorized* iPhone and harvest the resulting `.ips` crash log — **confirmation, not analysis**. Opt-in, require a connected device + `libimobiledevice` — see [docs/ON-DEVICE-TARGET.md](docs/ON-DEVICE-TARGET.md) |

New authorized research-device targets plug in behind the same interface — see
[docs/RESEARCH-DEVICE.md](docs/RESEARCH-DEVICE.md). For real crashes without a
device, fuzz macOS system frameworks directly — see
[docs/MAC-FUZZING.md](docs/MAC-FUZZING.md); to **confirm** a Mac-discovered
crash on real hardware, use the on-device target — see
[docs/ON-DEVICE-TARGET.md](docs/ON-DEVICE-TARGET.md).

### Apple Security Bounty evidence readiness

Check local report evidence and export a deterministic, redacted reference pack
for responsible disclosure:

```bash
ios-research report bounty-validate <report-id> --metadata researcher.json
ios-research report bounty-export <report-id> --metadata researcher.json
```

This is an evidence-completeness check, not an eligibility or reward decision.
It remains local-only: it does not access Apple systems or Target Flags. See
[docs/APPLE-BOUNTY-READINESS.md](docs/APPLE-BOUNTY-READINESS.md).

## For LLM agents

The full CLI is described in a machine-readable schema
([docs/cli-schema.json](docs/cli-schema.json), or `ios-research agent inspect`).
See [AGENTS.md](AGENTS.md) for the operating contract and recommended workflow.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) / [FINAL_ARCHITECTURE.md](FINAL_ARCHITECTURE.md)
- [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) — full command reference
- [SECURITY.md](SECURITY.md) / [SECURITY_AUDIT.md](SECURITY_AUDIT.md)
- [TEST_REPORT.md](TEST_REPORT.md) — 122 tests, 88% branch coverage
- [CONTRIBUTING.md](CONTRIBUTING.md) · [docs/PHASE-STATUS.md](docs/PHASE-STATUS.md)

## Development

The design prompts (`docs/PROMPT-*.md`) and optimization goals (`goals/*.json`)
describe the framework and how each phase was built.

## License

Released under the [MIT License](LICENSE).

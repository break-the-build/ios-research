# ios-research

Planning and specification material for **ios-research**, an authorized iOS security research framework designed for use by human researchers and LLM agents (such as Claude Code).

This repository currently contains the **design prompts** and **optimization goal specifications** that define the framework — not an implementation.

## What's here

- **`docs/`** — Prompt documents describing the architecture and each module of the framework: CLI runtime, corpus fuzzing, crash triage, exploitability analysis, differential testing, vulnerability reporting, LLM/agent operation, research orchestration, and audit hardening.
- **`goals/`** — Machine-readable JSON goal specifications (metrics, constraints, safety rules, and budgets) used to drive and evaluate research experiments.

## Scope and design

The framework is specified as a single, cohesive CLI (`ios-research <command>`) built around modular research targets, supporting:

- Reproducible, resumable research experiments
- Corpus management, fuzzing, and crash detection
- Crash triage, testcase minimization, and root-cause analysis
- Differential testing and vulnerability reporting
- Human-readable and stable JSON output
- Mock targets for CI, macOS-first development

## Safety boundaries

This project is intended for **authorized security research only**. The design explicitly excludes:

- Covert surveillance
- Camera/microphone permission bypass
- Persistence mechanisms
- Credential theft

Use it only against systems and targets you are authorized to test.

## License

Released under the [MIT License](LICENSE).

# Contributing

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the CLI:

```bash
ios-research --help
```

## Tests

```bash
pytest                 # full suite
pytest --cov=ios_research --cov-report=term-missing
pytest tests/test_agent.py          # focused development loop
```

Tests run against a temporary workspace with a frozen clock
(`IOS_RESEARCH_FROZEN_TIME`) so results are deterministic.

## Conventions

- **Determinism**: derive IDs/hashes from stable inputs; route timestamps
  through `ios_research.clock`.
- **Immutability**: prefer returning new objects over mutating inputs.
- **Small modules**: keep files focused; one command group per module under
  `commands/`.
- **Safety**: never add a capability listed as forbidden in `SECURITY.md`.
  New capabilities that touch the boundary must go through `safety.assert_allowed`.
- **JSON contract**: every command must support `--json` and keep its envelope
  stable.

## Documentation

Lessons from the 2026-08-25 docs audit ([#292](https://github.com/break-the-build/ios-research/issues/292)):

- **Generated docs are never hand-edited.** [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)
  renders from `build_cli_schema()` (`python tools/gen_cli_reference.py`) and
  [docs/cli-schema.json](docs/cli-schema.json) is emitted by
  `ios-research agent schema`. After changing CLI registration, regenerate
  both; CI fails if either drifts.
- **Point-in-time measurements are labeled as snapshots** and move to
  `docs/archive/` when they stop describing the present (e.g.
  `EXPERIMENT-LOOP-RESULTS.md`). Never update numbers in an archival doc;
  write a fresh one instead.
- **One narrative per topic.** Don't fork a second document that retells the
  architecture; extend the canonical one so they can't rot independently.
- **Naming**: root-level and `docs/` documents use SCREAMING-KEBAB-CASE
  (`CVE-REGRESSION.md`); generated artifacts keep their committed names
  (`cli-schema.json`, `CLI_REFERENCE.md`).
- **Research session output stays out of version control**
  (`research/findings/`, `research/RESEARCH-LOG.md` are gitignored).
  Unpublished vulnerability details must never enter the repository.

## Commit style

Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.

## First contribution

Start with an issue labelled `good first issue` or `help wanted`, leave a
comment describing the intended approach, then make a focused pull request.
For a safe local walkthrough, run the mock-target flow in
[docs/RESPONSIBLE-RESEARCH-STARTER.md](docs/RESPONSIBLE-RESEARCH-STARTER.md).
The project architecture is organized around `commands/` (CLI groups),
`targets/` (target adapters), and persistent campaign/workspace modules.

See [GOVERNANCE.md](GOVERNANCE.md) for review expectations, the safety-boundary
approval rules, and how substantial proposals are prioritized.

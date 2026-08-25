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

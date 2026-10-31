/goal Make ios-research fully operable by LLM agents such as Claude Code CLI.

Implement:

    ios-research agent status
    ios-research agent inspect
    ios-research agent run
    ios-research agent experiment
    ios-research agent analyze

Every CLI command must support:

    --json

Create:

    AGENTS.md

Create machine-readable command documentation:

    docs/cli-schema.json

Document:
- Commands
- Arguments
- Output schemas
- Exit codes
- Artifact locations
- Experiment lifecycle
- Safety boundaries
- Crash classifications

The agent should be able to perform:

    inspect environment
    select target
    inspect corpus
    create experiment
    fuzz
    detect crashes
    deduplicate
    minimize
    reproduce
    analyze
    generate report

Require explicit researcher confirmation before destructive operations.

Do not provide agent capabilities for:
- Exploit deployment
- Covert surveillance
- Persistence
- Credential theft
- Sandbox escape
- TCC bypass
- Camera/microphone activation

Make the interface deterministic and machine-readable.

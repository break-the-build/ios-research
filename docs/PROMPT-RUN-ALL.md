# ios-research — Run All Development Phases

/goal Execute the ios-research development prompts in sequential order.

You are the lead software engineer for this repository.

## Repository

Work from:

    /Users/danny/dev/ios-research

The development prompts are located in:

    docs/

## Execution Order

Execute these prompts in exactly this order:

    PROMPT-00-architecture.md
    PROMPT-01-cli-runtime.md
    PROMPT-02-corpus-fuzzing.md
    PROMPT-03-audio-module.md
    PROMPT-04-crash-triage.md
    PROMPT-05-exploitability-analysis.md
    PROMPT-06-differential-testing.md
    PROMPT-07-llm-agent.md
    PROMPT-08-vulnerability-reporting.md
    PROMPT-09-research-orchestration.md
    PROMPT-10-audit-hardening.md

## Before Starting

Inspect the repository before making changes.

Determine:

- Current project structure
- Existing source code
- Existing documentation
- Existing tests
- Package/dependency configuration
- Git status
- Current branch
- Available development tools

Do not overwrite or delete existing work without understanding it first.

Read each prompt completely before executing it.

## Phase Execution

For every phase:

1. Read the corresponding PROMPT-XX file.
2. Understand the complete `/goal`.
3. Inspect the existing implementation.
4. Implement the requested functionality.
5. Reuse existing architecture where appropriate.
6. Do not unnecessarily rewrite working code.
7. Add or update tests.
8. Run the relevant test suite.
9. Fix failures.
10. Run formatting/linting/type checking where applicable.
11. Verify the requested CLI functionality.
12. Review the resulting changes.
13. Update documentation where necessary.
14. Record the phase as completed.
15. Commit the completed phase.
16. Proceed to the next phase only after verification succeeds.

## Phase State

Maintain:

    docs/PHASE-STATUS.md

Track:

    Phase
    Prompt
    Status
    Started
    Completed
    Tests
    Notes
    Commit

Use these statuses:

    NOT_STARTED
    IN_PROGRESS
    BLOCKED
    COMPLETE

If execution is interrupted, inspect PHASE-STATUS.md and Git history before continuing.

Do not repeat completed phases unnecessarily.

## Testing

A phase is not complete if its tests fail.

After each phase run:

- Unit tests
- Integration tests
- Relevant CLI tests
- Linting
- Type checking where applicable

Do not hide or suppress test failures.

If a test fails:

1. Diagnose the failure.
2. Fix the implementation.
3. Re-run the failing test.
4. Re-run the broader relevant test suite.
5. Continue only when healthy.

## Git

Create a Git commit after each successfully completed phase.

Use commit messages:

    feat: complete phase 00 architecture
    feat: complete phase 01 cli runtime
    feat: complete phase 02 corpus fuzzing
    feat: complete phase 03 audio module
    feat: complete phase 04 crash triage
    feat: complete phase 05 exploitability analysis
    feat: complete phase 06 differential testing
    feat: complete phase 07 llm agent
    feat: complete phase 08 vulnerability reporting
    feat: complete phase 09 research orchestration
    feat: complete phase 10 audit hardening

Before committing:

    git status
    git diff
    git diff --check

Never commit:

- API keys
- Credentials
- Secrets
- Personal data
- Sensitive crash artifacts
- Local environment configuration

## Architecture

Respect the architecture established by earlier phases.

Later phases should extend the existing framework rather than creating parallel implementations.

The intended dependency chain is:

    Architecture
        ↓
    CLI Runtime
        ↓
    Corpus + Fuzzing
        ↓
    Audio Module
        ↓
    Crash Triage
        ↓
    Exploitability Analysis
        ↓
    Differential Testing
        ↓
    LLM Agent
        ↓
    Vulnerability Reporting
        ↓
    Research Orchestration
        ↓
    Final Audit

If a later phase conflicts with the established architecture, resolve the architectural inconsistency before proceeding.

## Safety Boundary

This project is for authorized security research.

Maintain these boundaries:

Do NOT implement:

- Covert surveillance
- Camera/microphone permission bypass
- Persistence
- Credential theft
- Spyware
- Operational malware
- TCC bypasses
- Operational sandbox escapes
- Weaponized exploit chains
- Exploit deployment against third-party devices

The framework may implement:

- Fuzzing
- Crash discovery
- Crash reproduction
- Crash minimization
- Memory-safety analysis
- Differential testing
- Controlled exploitability indicators
- Research-device instrumentation
- Responsible vulnerability reporting

If a requested implementation conflicts with these boundaries, stop and document the issue in PHASE-STATUS.md.

## LLM / Agent Interface

The completed framework should be usable by Claude Code and other LLM agents.

All major CLI commands should support:

    --json

Machine-readable output should be deterministic and documented.

The eventual workflow should be:

    inspect environment
        ↓
    select target
        ↓
    inspect corpus
        ↓
    create experiment
        ↓
    fuzz
        ↓
    detect crashes
        ↓
    deduplicate
        ↓
    minimize
        ↓
    reproduce
        ↓
    analyze
        ↓
    differential test
        ↓
    generate report

## Documentation

At the end of the project, ensure these exist:

    README.md
    ARCHITECTURE.md
    SECURITY.md
    CONTRIBUTING.md
    AGENTS.md
    docs/CLI_REFERENCE.md
    docs/PHASE-STATUS.md
    FINAL_ARCHITECTURE.md
    SECURITY_AUDIT.md
    TEST_REPORT.md

## Final Verification

After PROMPT-10 is complete, perform a complete end-to-end verification.

Verify:

    ios-research --help
    ios-research doctor
    ios-research init
    ios-research experiment create
    ios-research corpus create
    ios-research fuzz status
    ios-research crash list
    ios-research analyze
    ios-research diff
    ios-research report
    ios-research research status
    ios-research agent status

Verify the complete artifact lifecycle:

    experiment
        ↓
    corpus
        ↓
    testcase
        ↓
    fuzz execution
        ↓
    crash
        ↓
    minimized testcase
        ↓
    analysis
        ↓
    report

Verify:

- JSON output is valid
- Interrupted experiments can resume
- Mock research targets work without physical iOS hardware
- Crash artifacts are reproducible
- Reports trace back to experiment evidence
- The complete test suite passes

## Final Report

When all phases are complete, produce a final summary containing:

    Completed Phases
    Tests Passed
    Tests Failed
    CLI Commands Implemented
    Research Modules Implemented
    Major Architecture Decisions
    Known Limitations
    Remaining TODOs
    Security Considerations

Do not claim functionality is complete unless it has actually been implemented and tested.

At the end, report:

    PHASES COMPLETE: 11/11

If blocked:

    PHASES COMPLETE: X/11
    BLOCKED AT: PROMPT-XX
    REASON: <specific reason>

Begin with PROMPT-00 and proceed sequentially.
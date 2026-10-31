/goal Perform a complete engineering, security, and reliability audit of ios-research.

Review the entire repository for:
- Architectural inconsistencies
- Duplicated functionality
- CLI reliability
- Nondeterministic experiments
- Race conditions
- Artifact corruption
- Crash deduplication problems
- Error handling
- Missing tests
- Documentation gaps
- Unstable JSON schemas
- Unsafe destructive operations
- Credential leakage
- Sensitive data accidentally written to logs
- Inadequate experiment isolation

Run the complete test suite.

Add missing:
- Unit tests
- Integration tests
- Regression tests
- End-to-end tests

Verify:

    ios-research --help
    ios-research doctor
    ios-research experiment create
    ios-research corpus create
    ios-research fuzz start
    ios-research crash list
    ios-research crash minimize
    ios-research analyze
    ios-research diff
    ios-research report create
    ios-research research run
    ios-research research summarize

Verify every command supports machine-readable JSON output.

Verify interrupted experiments can resume.

Verify this artifact chain:

    experiment
      -> testcase
      -> crash
      -> minimized testcase
      -> analysis
      -> report

Produce:

    FINAL_ARCHITECTURE.md
    SECURITY_AUDIT.md
    CLI_REFERENCE.md
    TEST_REPORT.md

Do not add exploit-generation or covert-surveillance capabilities.

Fix identified issues rather than merely documenting them.

Run all tests again after remediation.

/goal Integrate ios-research into an end-to-end research orchestrator.

Implement:

    ios-research research create
    ios-research research run
    ios-research research status
    ios-research research pause
    ios-research research resume
    ios-research research summarize

A research run should support:

    Environment discovery
    Target selection
    Corpus validation
    Corpus mutation
    Fuzzing
    Crash detection
    Deduplication
    Minimization
    Reproduction
    Root-cause analysis
    Differential testing
    Research summary

Persist state so interrupted research runs can resume.

Add resource controls:
- Maximum runtime
- Maximum workers
- Maximum storage
- Maximum testcase count

Require confirmation before destructive operations.

Implement:

    ios-research research summarize <id>

The summary should include:
- Experiments performed
- Targets tested
- Testcases generated
- Crashes found
- Unique crashes
- Reproducible crashes
- Minimized crashes
- Potential memory-safety issues
- Differential findings
- Recommended next research steps

Ensure all components work together through mock targets in CI.

Do not implement weaponized exploit chains or covert access to device sensors.

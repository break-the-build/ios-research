/goal Build the core ios-research CLI and research runtime.

Implement:

    ios-research init
    ios-research doctor
    ios-research config
    ios-research device
    ios-research target
    ios-research experiment

Support:

    --json
    --verbose
    --quiet
    --config
    --workspace

Create a workspace structure containing:

    config
    experiments
    devices
    targets
    corpus
    crashes
    artifacts
    reports
    logs

Every experiment must have:
- Experiment ID
- Timestamp
- Target
- Device
- OS version
- Framework version
- Configuration hash

Implement device and target abstraction interfaces.

Provide mock implementations for CI.

Implement structured logging, stable exit codes, configuration management, and artifact tracking.

Add comprehensive tests.

Do not implement vulnerability exploitation.

Run all tests before completing the phase.

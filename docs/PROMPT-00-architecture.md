/goal Build the architecture and project foundation for ios-research, an authorized iOS security research framework.

Create a single cohesive CLI-driven framework designed for human researchers and LLM agents such as Claude Code.

The framework should support:
- Research experiments
- Device and target management
- Corpus management
- Fuzzing
- Crash detection
- Crash triage
- Testcase minimization
- Root-cause analysis
- Differential testing
- Vulnerability reporting
- LLM/agent operation

Primary CLI:

    ios-research <command>

Design the system around modular research targets so additional attack surfaces can be added later.

Create the repository architecture, core interfaces, configuration system, structured logging, artifact model, experiment model, plugin/module interfaces, CLI framework, and documentation.

Support:
- Human-readable CLI output
- Stable JSON output
- Reproducible experiments
- Structured artifacts
- Resumable operations
- macOS-first development
- Mock targets for CI

Establish clear safety boundaries:
- Authorized research only
- No covert surveillance
- No camera/microphone permission bypass
- No persistence
- No credential theft
- No operational spyware
- No weaponized exploit chains

Create the initial documentation and test suite.

Do not implement advanced fuzzing yet.

Run all tests before completing the phase.

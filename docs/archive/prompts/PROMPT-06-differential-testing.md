/goal Add differential testing and regression analysis to ios-research.

Implement:

    ios-research diff create
    ios-research diff run
    ios-research diff compare
    ios-research diff report

Support comparisons between:
- iOS versions
- Simulator/runtime versions
- Parser implementations
- Framework versions
- Configurations

For each testcase record:
- Target A
- Target B
- Input hash
- Result A
- Result B
- Diagnostic differences

Identify transitions such as:

    ACCEPT -> CRASH
    REJECT -> ACCEPT
    NORMAL -> TIMEOUT
    NORMAL -> CRASH

Implement regression detection.

Create reproducible differential experiments containing:
- Corpus
- Targets
- Versions
- Seeds
- Configuration
- Expected result

Do not implement exploit development.

Add automated tests for differential behavior.

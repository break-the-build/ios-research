/goal Build crash detection, triage, deduplication, reproduction, and testcase minimization.

Implement:

    ios-research crash list
    ios-research crash show <id>
    ios-research crash reproduce <id>
    ios-research crash minimize <id>
    ios-research crash classify <id>
    ios-research crash compare <id1> <id2>

Classify crashes such as:

    NULL_DEREFERENCE
    OUT_OF_BOUNDS_READ
    OUT_OF_BOUNDS_WRITE
    USE_AFTER_FREE
    INTEGER_ERROR
    TYPE_CONFUSION
    ASSERTION
    TIMEOUT
    UNKNOWN

Do not infer exploitability solely from crash type.

Implement testcase minimization using delta debugging or equivalent.

A minimized testcase must preserve the crash signature.

Store:

    crash.json
    original-input
    minimized-input
    diagnostics/
    analysis.json

Implement deterministic reproduction.

Create a regression corpus for previously discovered crashes.

Provide both human-readable and JSON analysis.

Do not implement weaponized exploit generation.

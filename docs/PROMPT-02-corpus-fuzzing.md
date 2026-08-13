/goal Build the corpus-management and fuzzing subsystem for ios-research.

Implement:

    ios-research corpus create
    ios-research corpus import
    ios-research corpus list
    ios-research corpus inspect
    ios-research corpus dedupe
    ios-research corpus minimize

Implement a generic fuzzing target interface:

    prepare()
    execute(input)
    collect_result()
    cleanup()

Support mutation strategies including:
- Byte mutation
- Truncation
- Insertion
- Deletion
- Boundary mutation
- Integer mutation
- Structure-aware mutation

Support deterministic seeds.

Track testcase lineage and metadata.

Implement:

    ios-research fuzz start
    ios-research fuzz stop
    ios-research fuzz pause
    ios-research fuzz resume
    ios-research fuzz status
    ios-research fuzz stats

Support:
- Workers
- Seeds
- Duration
- Maximum cases
- Targets
- Corpora
- JSON output

Create a mock parser target for testing.

Only identify abnormal behavior and crashes.

Do not implement exploit payload generation.

Add deterministic regression tests.

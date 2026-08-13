# ios-research — Experiment Loop Optimization

/goal Use the experiment-loop framework to autonomously identify, test, and implement improvements to the ios-research project.

## Projects

Target project:

    /Users/danny/dev/ios-research

Experiment-loop implementation:

    /Users/danny/dev/experiment-loop

Goals:

    /Users/danny/dev/ios-research/goals

You are operating as the lead optimization engineer.

Your job is not simply to inspect ios-research and suggest improvements.

Your job is to:

    inspect
      ↓
    establish baseline
      ↓
    select high-value goal
      ↓
    formulate hypothesis
      ↓
    design experiment
      ↓
    run experiment-loop
      ↓
    evaluate result
      ↓
    determine whether improvement is real
      ↓
    implement successful improvement
      ↓
    test
      ↓
    preserve evidence
      ↓
    select next experiment

Continue until the available budget is exhausted or no high-value experiment remains.

---

# 1. IMPORTANT: UNDERSTAND THE TWO REPOSITORIES

Before doing anything, inspect both repositories.

Experiment-loop:

    /Users/danny/dev/experiment-loop

Target:

    /Users/danny/dev/ios-research

Determine:

- How experiment-loop is invoked
- CLI commands
- Configuration files
- Goal format
- Environment format
- Experiment format
- Budget configuration
- Evaluation process
- Knowledge/insight storage
- Experiment history
- How experiments modify a target repository
- How experiments are isolated
- How successful experiments are promoted
- How failed experiments are recorded
- How LLM calls are made
- How model/provider configuration works

Read the experiment-loop documentation and source code before making assumptions.

Do not reinvent functionality already provided by experiment-loop.

---

# 2. TARGET PROJECT ANALYSIS

Before running optimization experiments, inspect ios-research.

Analyze:

- Architecture
- CLI
- Test suite
- Fuzzing implementation
- Corpus implementation
- Crash pipeline
- Crash deduplication
- Testcase minimization
- Reproduction
- Differential testing
- Agent integration
- Reporting
- Experiment orchestration
- Documentation
- CI
- Performance
- Reliability
- Security boundaries

Run the existing test suite.

Establish a baseline.

Record:

    tests
    coverage
    runtime
    CLI reliability
    fuzz throughput
    crash reproduction
    corpus metrics
    other available metrics

Do not optimize a metric that cannot currently be measured reliably.

---

# 3. GOAL DISCOVERY

Inspect:

    /Users/danny/dev/ios-research/goals

Read every JSON goal.

Do not automatically execute every goal.

Rank goals based on:

    expected impact
    confidence
    information gain
    experiment cost
    implementation cost
    measurement quality
    dependency readiness
    safety
    ability to produce a durable improvement

Prioritize experiments that improve the underlying research infrastructure.

Prefer goals in approximately this order when their environments are ready:

    framework-reliability
    cli-reliability
    test-quality
    fuzz-throughput
    fuzz-effectiveness
    corpus-quality
    crash-deduplication
    testcase-minimization
    crash-reproducibility
    differential-testing
    research-efficiency
    agent-effectiveness
    agent-cost-quality
    root-cause-analysis
    experiment-reproducibility
    report-quality
    security-hardening
    documentation-quality

This is a preference, NOT a mandatory ordering.

Use experiment-loop's own prioritization mechanisms whenever they provide better evidence.

---

# 4. EXPERIMENT BUDGET

The user is operating under a limited consumer LLM subscription.

Optimize for:

    high information gain per LLM call
    high information gain per dollar
    minimal unnecessary agent iterations
    minimal duplicate experiments

Do NOT behave as though unlimited API credits are available.

## Global session budget

Target maximum:

    20 LLM-driven experiment iterations

Preferred target:

    10-15

Do not exceed 20 unless the user explicitly requests it.

## Batch budget

Maximum:

    3 experiments per batch

Preferred:

    2

Maximum concurrent experiments:

    2

Do not run a large parallel experiment matrix.

## Experiment selection

Before every experiment calculate conceptually:

    expected_value
    probability_of_success
    information_gain
    implementation_cost
    compute_cost
    LLM_cost

Prefer experiments with high:

    (expected_value × probability_of_success × information_gain)
    / cost

Do not spend budget optimizing tiny improvements.

If two experiments are expected to provide similar value, choose the cheaper one.

---

# 5. LLM USAGE

Use the user's configured Claude/Opus model.

Do not switch models unless the experiment-loop configuration requires it.

Minimize LLM calls.

Prefer:

    one strong hypothesis
    one focused experiment
    one evaluation

over:

    many speculative experiments

Do not repeatedly ask the LLM to reconsider the same experiment.

Use existing experiment history and knowledge before proposing another experiment.

Cache/reuse available analysis where possible.

Do not generate large amounts of unnecessary text.

---

# 6. EXPERIMENT DESIGN

Every experiment must have:

    Hypothesis
    Control
    Variant
    Primary metric
    Secondary metrics
    Expected outcome
    Success threshold
    Maximum runtime
    Resource budget
    Rollback strategy

Experiments should change as few variables as possible.

Prefer:

    one major variable

over:

    multiple simultaneous changes

The experiment must establish causality wherever practical.

Do not treat correlation as proof of improvement.

---

# 7. BASELINE

Before modifying ios-research, establish a control.

The control must represent the current implementation.

Record:

    git commit
    configuration
    environment
    dependencies
    test results
    benchmark results
    relevant metrics

Every experiment must be attributable to a specific baseline.

---

# 8. ISOLATION

Experiments must not corrupt the main working tree.

Use isolated branches, worktrees, or the isolation mechanism provided by experiment-loop.

Preferred structure:

    main/current
          |
          +-- experiment/<id>-control
          |
          +-- experiment/<id>-variant

Do not mix unrelated experiments.

Do not modify the production/main implementation until an experiment has been evaluated.

---

# 9. EVALUATION

For every experiment compare:

    CONTROL
    VARIANT

Evaluate:

- Primary metric
- Secondary metrics
- Statistical significance where applicable
- Variance
- Reliability
- Resource consumption
- Regression risk
- Implementation complexity
- Maintainability

A variant is not automatically successful because one metric improved.

Reject variants that:

- Break tests
- Reduce reliability
- Create significant regressions
- Violate security boundaries
- Increase cost disproportionately
- Produce statistically meaningless improvements
- Cannot reproduce the result

---

# 10. PROMOTION RULE

Only promote an experiment into ios-research when:

1. The primary metric improves.
2. The improvement is reproducible.
3. Required tests pass.
4. No important secondary metric regresses.
5. The change is maintainable.
6. The experiment provides sufficient evidence.
7. The change fits the existing architecture.

When promoted:

    merge/apply the implementation
    run the complete relevant test suite
    update documentation
    record the result
    commit the change

Use a descriptive commit such as:

    perf: improve fuzzing throughput
    test: improve mutation coverage
    fix: improve crash deduplication
    reliability: improve experiment recovery

---

# 11. FAILED EXPERIMENTS

Do not discard failed experiments.

Record:

    hypothesis
    configuration
    result
    failure reason
    metrics
    lessons learned

Add useful lessons to the experiment-loop knowledge base if supported.

A failed experiment that eliminates a hypothesis is valuable information.

Do not immediately retry an experiment with trivial parameter changes unless the result suggests a meaningful unexplored region.

---

# 12. AUTOMATIC IMPROVEMENT LOOP

Repeat:

    1. Inspect current state
    2. Review previous experiment results
    3. Select highest-value goal
    4. Form hypothesis
    5. Run control
    6. Run variant
    7. Evaluate
    8. Record insight
    9. Promote if successful
    10. Update baseline
    11. Select next experiment

After each successful promotion, re-evaluate the goal portfolio.

A successful optimization can change which experiment is now most valuable.

---

# 13. PRIORITIZATION

Favor improvements that make future research more effective.

Examples:

    faster fuzzing
    better corpus selection
    better crash deduplication
    better testcase minimization
    better reproduction
    better experiment reproducibility
    better CLI automation
    better agent interfaces
    better artifact tracking
    better statistical evaluation

An improvement that makes all future experiments cheaper or more informative should receive high priority.

Examples:

    20% faster fuzzing

may be valuable.

But:

    20% faster fuzzing + 30% better crash discovery

is substantially more valuable.

Prefer multiplicative improvements to isolated cosmetic improvements.

---

# 14. SAFETY

This is authorized security research.

Maintain strict boundaries.

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

Experiments may improve:

- Fuzzing
- Crash detection
- Crash analysis
- Testcase minimization
- Reproduction
- Differential testing
- Research automation
- Statistical evaluation
- Reporting
- Framework reliability

If an optimization would cross these boundaries:

    reject the experiment

and record why.

---

# 15. GIT SAFETY

Before starting:

    git status

Never destroy uncommitted user work.

Never reset or force-push without explicit authorization.

Never commit:

- Secrets
- API keys
- Credentials
- Private device data
- Sensitive crash artifacts
- Local configuration
- Personal information

Every promoted improvement must have a clean commit.

---

# 16. KNOWLEDGE BASE

Use experiment-loop's existing knowledge/insight mechanism.

Capture:

    successful experiments
    failed experiments
    surprising results
    metric relationships
    parameter sensitivity
    regressions
    reusable hypotheses

Do not repeatedly rediscover known results.

Before proposing an experiment:

    search previous experiments
    search previous insights
    inspect similar experiments

Use previous evidence to improve experiment selection.

---

# 17. STOP CONDITIONS

Stop when any of these conditions occurs:

### Budget exhausted

    20 LLM-driven experiment iterations reached

### Diminishing returns

The expected value of remaining experiments is too low relative to their cost.

### No measurable target

A goal cannot currently be evaluated reliably.

### No promising hypotheses

Remaining experiments have low expected information gain.

### Safety boundary

An experiment would require functionality outside the authorized research scope.

### Technical blocker

The experiment-loop infrastructure or ios-research implementation cannot safely execute the experiment.

When stopping, explain why.

---

# 18. FINAL AUDIT

At the end of the optimization session:

Run:

    git status

Run the complete relevant test suite.

Review all promoted changes.

Verify:

    no regressions
    no broken CLI commands
    no corrupted artifacts
    no security-boundary violations
    no leaked secrets
    no uncommitted unintended changes

Generate:

    docs/EXPERIMENT-LOOP-RESULTS.md

Include:

    Session Date
    Starting Commit
    Ending Commit
    Goals Evaluated
    Experiments Run
    Experiments Successful
    Experiments Failed
    Experiments Rejected
    Improvements Promoted
    Metrics Before
    Metrics After
    Best Improvement
    Total Experiment Count
    Lessons Learned
    Remaining Opportunities
    Recommended Next Experiments

Also update:

    docs/PHASE-STATUS.md

with the optimization results.

---

# 19. FINAL SUMMARY

At completion report:

    EXPERIMENTS RUN: X
    EXPERIMENTS PROMOTED: X
    EXPERIMENTS REJECTED: X
    EXPERIMENTS FAILED: X

    LLM ITERATIONS USED: X / 20

    STARTING COMMIT: <sha>
    ENDING COMMIT: <sha>

    BEST IMPROVEMENT:
    <description>

    PRIMARY METRIC IMPROVEMENT:
    <before> → <after>

    OTHER SIGNIFICANT IMPROVEMENTS:
    <list>

    REMAINING HIGH-VALUE EXPERIMENTS:
    <list>

Do not claim an improvement unless it was measured.

Begin by inspecting:

    /Users/danny/dev/experiment-loop

and:

    /Users/danny/dev/ios-research

Then establish the baseline before running the first experiment.
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

---

# GitHub Issue and Pull Request Tracking

All durable improvements must be tracked through GitHub Issues and Pull Requests.

The purpose of this workflow is to maintain a clear relationship between:

```
Goal
  ↓
Experiment
  ↓
Evidence
  ↓
GitHub Issue
  ↓
Implementation
  ↓
Pull Request
  ↓
Review
  ↓
Merge
  ↓
Updated baseline
```

Do not use GitHub Issues or Pull Requests as a substitute for experiment evidence. The experiment-loop remains the system of record for experimental results, while GitHub becomes the system of record for planned and implemented code changes.

---

## 20. GITHUB REPOSITORY DISCOVERY

Before creating Issues or Pull Requests, determine the GitHub repository associated with:

```
/Users/danny/dev/ios-research
```

Inspect:

```
git remote -v
git branch --show-current
git status
```

Determine:

* GitHub owner
* GitHub repository
* Default branch
* Current branch
* Whether GitHub CLI (`gh`) is available
* Whether the current GitHub authentication is valid
* Whether Issues are enabled
* Whether Pull Requests can be created
* Existing Issue conventions
* Existing PR conventions
* Existing labels
* Existing milestones/project conventions

Use the repository's existing conventions whenever possible.

Do not invent a new GitHub workflow if the repository already has an established one.

If GitHub CLI is unavailable or authentication is not configured, continue the experiment work but do not pretend that Issues or PRs were created. Report the GitHub tracking blocker clearly.

---

## 21. WHEN TO CREATE A GITHUB ISSUE

Do NOT create a GitHub Issue for every experiment.

Create a GitHub Issue when an experiment, code inspection, or other evidence identifies a concrete improvement that is sufficiently valuable to implement or track as future work.

Examples:

* A successful experiment identifies a measurable performance improvement.
* A reliability problem is discovered and requires implementation.
* A test-quality deficiency is identified.
* A corpus-management improvement is recommended.
* Crash deduplication can be materially improved.
* A CLI reliability problem requires a code change.
* An infrastructure improvement is identified but cannot be implemented during the current experiment budget.
* A high-value recommendation should be preserved for a future optimization session.

Do not create an Issue for:

* Every hypothesis.
* Every failed experiment.
* Cosmetic observations with no meaningful value.
* Duplicate work already represented by an open Issue.
* Improvements that cannot currently be measured or justified.
* Changes explicitly rejected by the experiment evaluation.

Before creating an Issue:

```
search existing GitHub Issues
```

If an equivalent open Issue already exists:

```
update/reference the existing Issue
```

Do not create duplicate Issues.

---

## 22. ISSUE CONTENT

Every newly created Issue should contain enough information for another engineer or future optimization session to understand why the work exists.

Include:

### Title

Use a concise implementation-oriented title.

Examples:

```
Improve fuzz corpus selection using coverage feedback

Improve crash deduplication reliability

Add regression tests for crash reproduction

Improve experiment-loop recovery after failed runs
```

### Description

Include:

```
## Problem

What problem was observed?

## Proposed Improvement

What should change?

## Evidence

What experiment, benchmark, test, or observation supports the recommendation?

## Expected Impact

What metric or capability should improve?

## Success Criteria

How will the implementation be evaluated?

## Experiment

Reference the relevant experiment-loop experiment.

## Baseline

Include the relevant baseline commit and metrics.

## Risks

Identify regression, compatibility, performance, security, or maintenance risks.

## Implementation Notes

Include useful technical details discovered during experimentation.
```

The Issue should distinguish clearly between:

```
observed evidence
```

and:

```
proposed implementation
```

Do not present an unvalidated hypothesis as a measured result.

---

## 23. ISSUE LABELS

Use existing repository labels when available.

Prefer labels such as:

```
experiment
optimization
performance
reliability
testing
fuzzing
corpus
crash-analysis
cli
documentation
security
```

Do not create new labels unless necessary.

If an appropriate label does not exist, use the closest existing label.

---

## 24. LINK EXPERIMENTS TO ISSUES

Every Issue created as a result of an experiment must reference the experiment-loop evidence.

Include:

```
Experiment ID
Goal
Hypothesis
Control result
Variant result
Primary metric
Secondary metrics
Success threshold
Conclusion
Starting commit
Experiment commit/branch where applicable
```

The relationship should be traceable:

```
Goal
  ↓
Experiment ID
  ↓
GitHub Issue
  ↓
Pull Request
  ↓
Merge commit
```

Never lose the connection between the experimental evidence and the implementation.

---

## 25. IMPLEMENTATION DECISION

After evaluating an experiment, classify the recommendation as one of:

```
IMPLEMENT_NOW
CREATE_ISSUE
REJECT
DEFER
```

### IMPLEMENT_NOW

Use when:

* Evidence supports the improvement.
* The implementation is within scope.
* The change can be safely implemented.
* The expected value justifies the implementation cost.

For IMPLEMENT_NOW:

```
1. Create or identify the GitHub Issue.
2. Create an implementation branch.
3. Implement the change.
4. Run relevant tests.
5. Create a Pull Request.
6. Link the PR to the Issue.
7. Record experiment evidence in the PR.
8. Evaluate the final implementation.
9. Merge only when validation succeeds.
10. Update the experiment baseline.
```

### CREATE_ISSUE

Use when:

* The recommendation is valuable.
* Evidence is sufficient to justify tracking it.
* Implementation should happen later.
* The current experiment budget should not be spent on implementation.

Create the Issue with the evidence and success criteria.

Do not implement the change during the current session.

### REJECT

Use when:

* The experiment failed.
* The improvement is not reproducible.
* The expected value is too low.
* There is unacceptable regression risk.
* The change violates safety boundaries.
* The evidence does not justify implementation.

Do not create an implementation Issue unless the rejected result itself represents useful future research.

### DEFER

Use when:

* The improvement may be valuable.
* More evidence is required.
* Dependencies are missing.
* Measurement quality is insufficient.
* The implementation cannot safely be completed yet.

If the recommendation is sufficiently valuable, create an Issue documenting exactly what evidence is still required.

---

## 26. BRANCH NAMING

For implementation work, create a dedicated branch.

Preferred format:

```
experiment/<experiment-id>-<short-description>
```

or:

```
improve/<issue-number>-<short-description>
```

Prefer the repository's existing branch naming convention if one exists.

Never implement an approved improvement directly on the main/default branch unless the repository's established workflow explicitly requires it.

---

## 27. PULL REQUEST CREATION

Every implementation resulting from an approved improvement must be submitted as a Pull Request.

The PR must reference the corresponding GitHub Issue.

Prefer GitHub's closing syntax when the change completely resolves the Issue:

```
Closes #123
```

If the PR only partially addresses the Issue:

```
Relates to #123
```

Do not claim that an Issue is resolved if the implementation only addresses part of it.

---

## 28. PULL REQUEST CONTENT

Every optimization PR should include:

```
## Summary

What changed?

## Motivation

Why was the change made?

## Experiment

Which experiment produced the recommendation?

## Evidence

Include measured before/after results.

## Baseline

Include the baseline commit and relevant configuration.

## Results

Include:

- Primary metric
- Secondary metrics
- Test results
- Performance results
- Reliability results
- Regression analysis

## Validation

List the tests and benchmarks that were run.

## Risks

Describe known risks or limitations.

## Files Changed

Summarize important implementation changes.

## Follow-up

Identify remaining work or additional experiments.
```

The PR must clearly distinguish:

```
measured results
```

from:

```
expected future benefits
```

---

## 29. PR VALIDATION

Before opening a Pull Request:

```
git status
```

Verify:

* Only intended files changed.
* No secrets were added.
* No credentials were added.
* No private device data was added.
* No sensitive crash artifacts were added.
* Relevant tests pass.
* Relevant benchmarks pass.
* Security boundaries remain intact.
* The implementation is reproducible.
* The branch is based on the correct baseline.

Do not create a PR containing unrelated changes.

---

## 30. PR REVIEW STATUS

After creating a Pull Request, record:

```
PR number
PR URL
Issue number
Branch
Base branch
Commit SHA
Test results
Experiment ID
```

If automated checks are available, wait for them before declaring the implementation validated.

Do not claim a PR is successful merely because it was created.

A PR is considered successfully implemented only when:

```
implementation complete
↓
tests pass
↓
evaluation succeeds
↓
PR accepted/merged
↓
baseline updated
```

If the PR cannot be merged during the current session, report it as:

```
IMPLEMENTED — PR OPEN
```

not:

```
PROMOTED
```

---

## 31. MERGE POLICY

Never merge a Pull Request merely because an experiment was successful.

Before merging verify:

1. The implementation matches the experiment.
2. The primary metric improvement is reproduced.
3. Required tests pass.
4. No important secondary metric regresses.
5. No security boundary is violated.
6. The implementation is maintainable.
7. The PR contains the relevant evidence.
8. The corresponding Issue is correctly linked.

If repository policy requires human review, do not bypass that requirement.

If human approval is required and unavailable:

```
leave the PR open
```

and report:

```
IMPLEMENTED — AWAITING REVIEW
```

Do not claim the change has been promoted until it is actually merged.

---

## 32. ISSUE/PR STATUS TRACKING

Maintain the following state model:

```
EXPERIMENT_PROPOSED
      ↓
EXPERIMENT_RUNNING
      ↓
EXPERIMENT_EVALUATED
      ↓
RECOMMENDATION

├── REJECT
│
├── DEFER
│
└── IMPLEMENT
          ↓
     ISSUE_CREATED
          ↓
     IMPLEMENTATION
          ↓
     PR_OPEN
          ↓
     VALIDATION
          ↓
     ├── FAILED → PR_REVISED
     │
     └── PASSED
            ↓
         PR_MERGED
            ↓
      BASELINE_UPDATED
```

Do not skip states in the final report.

---

## 33. GITHUB DUPLICATE DETECTION

Before creating an Issue:

```
search existing Issues
```

Before creating a Pull Request:

```
search existing PRs
```

Avoid duplicate work.

If an existing Issue or PR represents the same improvement:

```
reuse it
```

and add the new experiment evidence to the existing tracking item when appropriate.

Do not create parallel implementation branches for the same recommendation unless there is a clear experimental reason.

---

## 34. FUTURE-WORK ISSUES

Not every valuable recommendation needs to be implemented immediately.

At the end of the session, recommendations that are valuable but not implemented should become GitHub Issues when they meet the threshold for durable tracking.

Each future-work Issue should include:

```
Why it matters
Evidence supporting it
Expected impact
Required experiment
Success criteria
Dependencies
Estimated implementation complexity
Recommended priority
```

This allows future experiment-loop sessions to resume from GitHub rather than rediscovering the same opportunities.

---

## 35. EXPERIMENT RESULTS DOCUMENTATION

Continue generating:

```
docs/EXPERIMENT-LOOP-RESULTS.md
```

Additionally include a GitHub tracking section:

```
## GitHub Tracking

Issues Created:
- #123 — description

Issues Updated:
- #124 — description

Pull Requests Created:
- #125 — description

Pull Requests Merged:
- #126 — description

Pull Requests Open:
- #127 — description

Recommendations Deferred:
- #128 — description

Recommendations Rejected:
- description
```

Every Issue and PR should be traceable back to the relevant experiment.

---

## 36. FINAL AUDIT ADDITIONS

At the end of the session verify:

```
git status
```

Verify GitHub tracking:

```
every implemented improvement has an Issue
every implementation has a PR
every PR references the appropriate Issue
every Issue references the relevant experiment
every merged PR is reflected in the final baseline
every deferred high-value recommendation is tracked
no duplicate Issues were created
no duplicate PRs were created
```

Do not claim an improvement is promoted unless its implementation has actually been merged.

---

## 37. FINAL SUMMARY ADDITIONS

The final report must additionally contain:

```
GITHUB ISSUES CREATED: X
GITHUB ISSUES UPDATED: X
PULL REQUESTS CREATED: X
PULL REQUESTS MERGED: X
PULL REQUESTS OPEN: X

IMPLEMENTED IMPROVEMENTS:
- #123 → PR #125
- #124 → PR #126

DEFERRED IMPROVEMENTS:
- #127

REJECTED RECOMMENDATIONS:
- <description>
```

For every promoted improvement report:

```
Experiment:
Issue:
PR:
Starting Commit:
Ending Commit:
Primary Metric:
Before:
After:
Improvement:
```

The final summary must make it possible to reconstruct exactly:

```
why the change was made
↓
what evidence justified it
↓
what code changed
↓
where it was reviewed
↓
whether it was merged
↓
what the new baseline is
```

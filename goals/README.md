# Experiment-loop goal portfolio

The JSON files in this directory are executable search definitions.  They are
not, by themselves, evidence that a change improves a real iOS research
campaign.  This document defines how their results may be used.

## Numbering convention

Goal numbers organize the portfolio, but they are **not unique identifiers**:
variants that implement one goal share its number (e.g.
`05-fuzz-throughput.json` and `05-fuzz-throughput-engine.json`; `18-framework-reliability.json`
and `18-on-device-matching.json`). The canonical machine identifier is the
`name` field inside each file (`iosr-*-v1`), which is also what logs and
experiment records reference — cite that, not the bare number.

## Evidence classes

| Class | Goal environments | Permitted conclusion |
| --- | --- | --- |
| Release quality gate | 01-04, 16, 18-framework, 19, 20 | The checked invariant passed or failed. These are CI gates, not optimizer campaigns. |
| Deterministic simulator | 05-15 and 17 | A configuration improved a defined local model. It is a hypothesis for external validation, not a product-performance claim. |
| Device-matching simulation | 18-on-device | The attribution logic improved against seeded busy-device scenarios. It is not a measurement from physical hardware. |
| Evidence-readiness simulation | 21, 23, 24 | The pipeline produced a more complete/deterministic evidence pack or faster stage profile against the framework's own validators. Not a claim of bounty eligibility. |
| Self-consistency detection benchmark | 22 | Rule-engine behavior matches its own documented indicators; not a malware-zoo evaluation. |
| Authorized target validation | Future environments enabled by issues #29, #30, #31, #33, #36-#39 and #49 | A result measured on a declared, authorized target matrix with retained artifacts. This is eligible for a product-performance claim. |

## Bounty alignment

The portfolio's ultimate purpose is submission-quality evidence for the
**Apple Security Bounty** program via authorized research. Goal 21
(`iosr-bounty-evidence-readiness-v1`) directly optimizes the local
evidence chain (`report bounty-validate` checklist + deterministic export);
goals 09/11/08/06 cover PoC minimization, classification, deduplication, and
reproducible discovery; goal 24 profiles turnaround latency per stage. See
[docs/GOALS-REVIEW.md](../docs/GOALS-REVIEW.md) for the full coverage matrix,
the first product insight (missing `affected_versions` provenance), and the
remaining gaps (real `mac:*` harness campaign goal is gated on harness
availability). Readiness metrics measure evidence completeness — they never
imply bounty eligibility.

## Promotion policy

A simulator result can be promoted only when all of the following are recorded
in the experiment result or linked issue:

1. A paired control/variant result with the configured statistical test and a
   practically meaningful effect size (default: at least 5% on the primary
   metric; justify any smaller threshold).
2. Every hard constraint passes in every reported validation arm.
3. The variant is re-run on a target/seed holdout not used to select it. For
   target-specific settings, the report must say so and must not claim general
   improvement.
4. The exact commit, goal ID, configuration, seeds, platform, toolchain, input
   corpus hashes, raw measurements, and generated artifacts are retained.
5. For any finding claimed outside a simulator, the target owner has authorized
   the test and the evidence includes reproduction and triage output.

For changes that affect on-device behavior, validate across the declared
device/OS/build matrix and report both false-attribution and miss rates. Do not
infer exploitability, security impact, or bounty eligibility from a crash alone.

## Metric rules

- `coverage_growth` and `coverage_per_input` are behavioral proxies in the
  current mock environments; they are not edge or block coverage. Use a future
  instrumented-coverage environment for coverage claims.
- `actionable_findings_per_dollar`, `quality_per_dollar`, and `token_usage` are
  local models in the current environments. Their units must be labelled
  `modeled` until wall-clock, CI, device, and API costs are captured.
- A signature, outcome transition, or mock crash is a candidate signal. It is
  not an independently verified vulnerability without an oracle and a
  reproducible authorized-target result.

## Stable identities and execution

Every executable goal has an explicit `id`. Never reuse an ID when changing a
goal's objective, primary metric, target population, or evidence class; create
a new goal instead. This preserves experiment-loop resume semantics and makes
the result lineage auditable.

The two historical filename-number collisions are intentional compatibility
paths and are disambiguated by ID:

| Filename | Goal ID |
| --- | --- |
| `05-fuzz-throughput.json` | `iosr-fuzz-throughput-inner-v1` |
| `05-fuzz-throughput-engine.json` | `iosr-fuzz-throughput-engine-v1` |
| `18-framework-reliability.json` | `iosr-framework-reliability-v1` |
| `18-on-device-matching.json` | `iosr-device-matching-v1` |

## Portfolio priority

Until authorized-target validation exists, prioritize capability delivery over
additional mutation-weight searches: coverage feedback (#29), constraint-aware
mutation (#30), normalized sanitizer triage (#31), the target SDK (#33), test
plan/device evidence and reproducibility (#36-#39), and regression fuzzing
(#49). Those capabilities make subsequent experiments representative enough to
inform product decisions.

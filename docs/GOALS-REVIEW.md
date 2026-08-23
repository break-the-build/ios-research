# Experiment-loop goals review (2026-08-23)

Review scope: every goal in [`goals/`](../goals/), its environment binding in
[`tools/experiment_loop/ios_env/`](../tools/experiment_loop/ios_env/), coverage
of framework functionality, and alignment with the framework's stated ultimate
purpose — producing submission-quality evidence for the **Apple Security
Bounty** program through authorized research only.

## 1. Coverage: functionality vs. goals

| Framework area | Goal(s) | Environment executable today |
|---|---|---|
| Test suite quality/coverage | 01, 02 | no (`ios_research_test_suite` unbound) |
| CLI reliability / latency | 03, 04 | no (`ios_research_cli` unbound) |
| Fuzz throughput | 05 | yes |
| Fuzz effectiveness | 06 | yes |
| Corpus quality | 07 | yes |
| Crash deduplication / classification | 08, 11 | yes |
| Testcase minimization | 09 | yes |
| Crash reproducibility | 10 | no (`ios_research_reproduction` unbound) |
| Differential testing | 12 | yes |
| Research efficiency / reliability / reproducibility | 13, 16, 18-framework | yes |
| Agent effectiveness / cost | 14, 15 | yes |
| Report quality | 17 | yes |
| On-device attribution | 18-on-device | yes |
| Security hardening | 19 | no (`ios_research_security` unbound) |
| Documentation | 20 | no (`ios_research_documentation` unbound) |
| Detection signatures | **22 (new)** | **yes** |
| CVE patch-regression integrity | **23 (new)** | **yes** |
| Pipeline latency observability | **24 (new)** | **yes** |

Previously uncovered and now closed by this review: detection signatures,
CVE regression validation, pipeline latency/stage observability, and — most
importantly — bounty evidence readiness (**21, new**).

## 2. Bounty alignment

Apple's program rewards *verified* memory-safety issues with reproducible,
well-documented submissions; triage quality and completeness of evidence
directly affect validation outcomes. Mapping the portfolio to the levers that
actually move submission quality:

| Submission lever | Portfolio coverage |
|---|---|
| Finding real crashes on Apple attack-surface parsers | 06/05 (mock simulators); **gap**: no goal bound to the real `mac:*` harness targets yet (gated on harness availability — see §4) |
| Reproducibility of the PoC | 10 (unbound env), 06 constraint ≥0.95, 18-on-device attribution |
| Minimal, clear PoC input | 09 minimization reduction |
| Correct classification/root cause | 11 classification accuracy |
| Complete, deterministic evidence pack | **21 bounty-evidence-readiness (new)** — drives `report bounty-validate` checklist pass rate with a hard export-determinism invariant |
| Fast turnaround from discovery to report | **24 pipeline-latency (new)** — stage-level wall-clock profile |
| No false positives wasting triage effort | **22 detection F1/FPR (new)**; 08 dedup F1 |

Deliberately **out of alignment by design**: nothing in the portfolio rewards
weaponization, persistence, surveillance, or exploit-chain work — those are
forbidden capabilities (`SECURITY.md`) and are not bounty prerequisites.

### First product insight from goal 21

Running the new readiness environment surfaced a concrete gap: reports built
by the standard pipeline miss the `affected_versions` check (no recorded
non-placeholder OS version) even after reproduce+minimize. Action: `report
create` should inherit target/OS provenance from the crash's experiment when
available. Tracked as a follow-up; goal 21 will verify the fix (pass rate
should reach 1.0 with both knobs on).

## 3. Quality / speed / observability assessment

- **Quality** — goals encode hard constraints where violations invalidate
  evidence (export determinism = 1.0 in 21; registry integrity & analog pass
  rate = gates in 23; FPR ≤ 0.05 in 22). The promotion policy in
  [`goals/README.md`](../goals/README.md) requires holdout validation before
  any claim.
- **Speed** — throughput/latency have dedicated goals (05 engine exec/s, 04
  CLI p95 once bound, 24 stage-level latency). New environments complete in
  milliseconds per sample so campaigns stay cheap (budgets capped ≤ $100).
- **Observability** — 24 emits per-stage timings every run; 21 exposes the
  full bounty-validate checklist outcome; 22 reports rules-loaded alongside
  F1 so rule-count changes cannot silently inflate scores. All environments
  emit mean/stdev/n per metric through the engine's `Observation`.

## 4. Remaining gaps (ordered by value)

1. **Bind `mac:*` real-harness campaign goal** (authorized-target class):
   highest-value step toward actual bounty findings; blocked on stable local
   harness builds (docs/MAC-FUZZING.md). Add `25-mac-campaign.json` +
   `ios_research_mac_campaign` environment when hardware gate clears.
2. **Implement deferred environments**: `ios_research_test_suite` (01/02),
   `ios_research_cli` (03/04), `ios_research_reproduction` (10),
   `ios_research_security` (19), `ios_research_documentation` (20).
3. **Fix `affected_versions` provenance** (see §2 insight).
4. **Matrix-reproducibility goal**: extend 18-on-device with cross-OS-version
   reproduction-rate metrics for multi-build submissions.

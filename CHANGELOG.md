# Changelog

All notable changes are documented here. This project follows
[Semantic Versioning](https://semver.org/): incompatible CLI/schema changes are
major releases, backward-compatible features are minor releases, and fixes are
patch releases.

## Unreleased

### Initial framework (phases 00–10)

- Deterministic CLI runtime with a stable JSON envelope, exit-code contract,
  workspace layout, content-addressed artifact store, and injectable clock.
- Corpus management, resumable/reproducible fuzz engine, crash store with
  signature deduplication, delta-debugging minimization, reproduction and
  classification.
- Evidence-gated exploitability analysis (never fabricates code-execution),
  differential testing with regression detection, responsible-disclosure
  report generation with evidence tracing, 12-stage resumable research
  orchestration, and a machine-readable CLI schema (`agent inspect`).

### Target families

- CI-safe mock parsers sharing defect models across ~25 families: record
  parser (+v2 differential variant), audio, Bluetooth, Wi-Fi, Wi-Fi Aware,
  NFC, messaging, locked-device, geodata/workout, filesystem-client,
  proximity app-protocol, signed-document, document-importer, XPC/Mach
  schema, IPC trust-boundary, Continuity beacons, PQ3 ratchet transcripts,
  IP-stack input path, lockscreen intents, JavaScriptCore semantics, and a
  `mach:sim` kernel message-boundary model.
- **Real-signal opt-ins**: in-process macOS libFuzzer/ASan harnesses
  (`mac:imageio`, `mac:audiotoolbox`, `mac:coregraphics`, `mac:coretext`,
  `mac:videotoolbox`) with a persistent-mode engine; black-box on-device
  confirmation targets (`ios-device:*`) over USB; opt-in Apple Security
  Research Device backend (safety-gated); virtual-device backend with
  deterministic snapshots.

### Fuzzing engine

- Optional coverage feedback with fair retained-input scheduling;
  constraint-guided mutation; grammar-aware mutator plugins; dictionaries and
  value profiles; LLM-in-the-loop proposal mutation with crash-aware rounds;
  directed greybox scheduling via call-graph distances with multi-symbol focus
  rotation; online strategy-weight adaptation; periodic checkpoint flushes;
  duplicate-input skipping; windowed generate-execute-reduce executor
  abstraction with threaded batches; stateful sequence fuzzing with
  minimization and replay lineage; post-run corpus distillation.

### Triage, analysis, and evidence

- SARIF finding import with adjudication workflow; engine-neutral artifact
  ingestion from external campaigns; sysdiagnose/video evidence references;
  TSan race-report ingestion with scheduling-perturbation hooks; device/OS
  matrix runs with reliability scoring; beta-release differential pipeline;
  public-advisory cross-referencing with novelty scoring; multi-agent
  suspicious-point triage; multi-sanitizer profiles including MTE/EMTE tag
  triage; metamorphic and property-based oracles; macOS reward-category
  verification oracles with Commpage/TCC Target-Flag capture detection.

### Platform tooling

- `staticscan`: Mach-O/dyld-shared-cache census, parser fingerprinting,
  evidence-backed dictionary generation, Ghidra call-graph normalization,
  binary/build diffing, shared-cache extraction.
- `nday`: IPSW symbol patch-diffing with reachability prioritization.
- `ipa`: authorized static/config analysis with local rule packs.
- `xcode`: test-plan adapter and XCResult diagnostic ingestion.
- `campaign`: continuous regression fuzzing with flaky triage and trends,
  distributed coordination with safe corpus exchange bundles, on-device
  confirmation bridge for Mac-discovered findings.
- `lockdown`: Lockdown Mode paired-run differential profile.
- `supply`: dependency vetting (requirements audit, behavior scan, lockfile
  drift verification).
- `suites`: versioned protocol/format suite catalog.
- `surface`: attack-surface inventory with bounty-EV campaign prioritization.

### Reporting and compliance

- Apple Security Bounty evidence-readiness validation/export with Target Flag
  taxonomy mapping; input-delivery provenance declaration (zero-click
  surfacing); defensive detection-signature engine with built-in rules;
  known-CVE patch-regression validation harness.

### Performance

- Batched hot-loop persistence (~8.8× execution throughput), concurrent ddmin
  rounds, parallel crash-triage fan-out, reduced corpus-manifest write
  amplification, bounded native-harness profiling.

### Documentation

- Security-testing handbook, reproducibility standard, release policy,
  community-health metrics, responsible-research starter, CLI reference now
  generated from the committed schema (`tools/gen_cli_reference.py`).

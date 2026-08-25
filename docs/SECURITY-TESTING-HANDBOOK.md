# iOS Security Testing Handbook

**The comprehensive guide to attack surface, techniques, and the ios-research
framework.** Companion documents: [ATTACK-SURFACE-MAP.md](../research/ATTACK-SURFACE-MAP.md)
(prioritized surface inventory), [IOS-SECURITY-OVERVIEW.md](../research/IOS-SECURITY-OVERVIEW.md)
(platform architecture), [SECURITY.md](../SECURITY.md) (capability boundary).

---

## Part I — Foundations

### 1. How to use this handbook

- **New to iOS security testing?** Read Part I fully, then Part III's
  lifecycle, then work backwards into the technique sections as needed.
- **Know the domain but new to this framework?** Skim Part II (what each
  component does), then use Part IV as your runbook when something pops.
- **Looking for what to test?** The attack-surface map scores every surface on
  reachability × severity × novelty × framework-fit; start at its ranked table.

Everything here assumes **authorized research on devices you own or are
contractually permitted to test** (Apple Security Research Device program,
your personal devices, or engagement scope). Nothing in this framework
deploys exploits, targets third parties, or bypasses protections on devices
you don't control — see §6.

### 2. The iOS security model — concepts a tester must know

You cannot find meaningful bugs without understanding what "meaningful"
means on this platform. iOS is the most aggressively hardened consumer OS in
production; the security model determines which bugs are *reachable*, which
are *exploitable*, and which are *rewardable*.

#### 2.1 Boot chain and trust roots

Every iOS device boots through a chain of signed images: Boot ROM (immutable,
in silicon) → LLB/iBoot → kernelcache. Each stage verifies the next against
Apple's root CA. Consequences for testers:

- No persistent code execution without a *signature* bypass — a crashed app
  returns to a clean state on relaunch; persistence itself is a finding.
- "Jailbroken device" testing changes the threat model entirely: you are no
  longer testing what Apple ships. Keep stock devices for evidence; use
  jailbroken ones (if at all) only for reconnaissance and understand the
  results don't transfer.

#### 2.2 The application sandbox

Every third-party app runs in aSeatBelt-profile sandbox with:
- **Container isolation** — filesystem access limited to the app's container
  plus explicitly shared locations (photo picker, document picker).
- **Entitlement-gated IPC** — talking to a system daemon requires the daemon
  to accept your connection; most sensitive Mach services check entitlements
  or audit tokens.
- **No raw sockets** — network access goes through the system stack.

Why this matters: a memory-corruption bug inside an app is *contained* unless
you also escape the sandbox. The bounty table reflects this — WebContent code
execution pays $10K; escaping the WebContent sandbox pays $300K; escaping
with kernel control pays $1M+. **Chains are the currency of the top tiers**
(entry bug → sandbox context → privilege escalation → demonstrated primitive).

#### 2.3 Parser separation (BlastDoor and descendants)

After the 2019-era iMessage attack wave, Apple moved untrusted input parsing
out of privileged processes into sandboxed, resource-limited "parser
services" — BlastDoor for iMessage, `mediaparserd` for media, similar
separation for link preview. Implications:

- A crash in a parser daemon is usually *contained by design* — the daemon
  dies, the message never renders, the user sees nothing. This is why
  `crash ≠ compromise` on iOS and why your report must argue *reachability*.
- The parser daemons still hold the bug classes (memory corruption in format
  parsers), and their crash logs are evidence-rich. Test the parser, argue
  the path into it.

#### 2.4 Mitigation generations (know your device's era)

Which bug classes are *demonstrable* depends on hardware generation. Record
the generation in your provenance (`mitigation` module does this):

| Generation | Mechanism | Effect on testing |
|---|---|---|
| Pre-A12 | Basic ASLR, ASan-free | Historical only |
| A12+ | PAC (pointer authentication) | ROP/JOP needs signed gadgets; control-flow hijack much harder |
| A15+ | **MIE** (Memory Isolation Extensions) | Kernel heap partitions isolated; cross-partition corruption blocked |
| A17+ / M-series | **EMTE** (Extended Memory Tagging Extension) | Synchronous tag check on every load/store — use-after-free and overflow become *immediate* faults, not exploitable primitives |

Practical consequences:
- EMTE devices turn latent memory bugs into hard crashes *in testing* — great
  for discovery, but the same bug on an EMTE device may be unexploitable,
  which changes the report's severity argument.
- A bug found on an M-generation device should be re-verified on older
  silicon if you want to argue broader impact (the SRD program lends
  devices across generations for exactly this).
- Kernel bugs that were "arbitrary R/W" in the PAC era may only be "denial of
  service" on EMTE. The bounty tiers track *demonstrated* outcomes, not bug
  class labels.

#### 2.5 Data protection and key hierarchy

Filesystem encryption keys derive from the passcode + hardware UID key.
Protection classes (`NSFileProtectionComplete*`) gate when keys are
unwrapped. The **$500K "physical access, locked device" bounty tier** is
about extracting sensitive data through *services that run while locked*
(notifications, widgets, USB services, Siri) — not about breaking AES.

#### 2.6 Network stack ownership

Apps don't own their network parsing: user-space daemons (`mDNSResponder`,
`networkd`, `CommCenter`, `WirelessRadioManagerd`) and the kernel's
`com.apple.network` subsystems parse most remote input. Zero-click attack
surface is dominated by these daemons plus push (APNs) and message
(BlastDoor) ingestion. The attack-surface map's Tier Z is essentially a
census of these daemons' input formats.

### 3. The bounty landscape (what "worth finding" means)

The full category table with rewards lives in the attack-surface map (§2).
The structural points a tester must internalize:

1. **Outcome beats bug class.** "Heap overflow" is not a reward; "heap
   overflow → PC control on the app processor, demonstrated via Target
   Flags" is.
2. **Target Flags are the proof language.** Apple's crash logs carry four
   commpage words (`_COMM_PAGE_ASB_TARGET_VALUE/ADDRESS` and
   `…_KERN_VALUE/ADDRESS`) that a report uses to demonstrate register
   control (32/64-bit) or arbitrary read/write. The framework's
   `targetflags` and `flagcapture` modules map crash evidence onto this
   taxonomy — see §14.
3. **Reachability multiplies everything.** Zero-click network × kernel
   control = $2M; the same kernel bug via a local app = a fraction.
4. **Bonuses**: +50% for findings in beta releases, +100% for Lockdown-Mode
   bypasses, +150% for both.
5. **DoS is not a category.** Hangs and resource exhaustion (like our
   FINDING-04 AudioToolbox loop) get acknowledgment and credit, not payment.
   Hunt memory corruption and logic/authorization bugs.

### 4. Threat-model-driven prioritization

Rank candidate surfaces by **expected value**, not by what's easy:

```
EV ∝ reachability × outcome_severity × novelty / crowding
```

- **Novelty is the highest-leverage variable.** Code shipped in the last 24
  months (Wi-Fi Aware, PQ3 ratchet, RCS, Apple Intelligence pipelines) has
  seen a fraction of the auditing WebKit has. A medium bug in new code
  outvalues a heroic bug in WebKit.
- **Crowding**: WebKit/JSC has thousands of researcher-years; proximity
  stacks and locked-device services have dozens.
- **Framework fit**: prefer surfaces you can actually exercise (host-side
  harness today, device confirmation on tap). The attack-surface map scores
  all of this per surface.

### 5. The tester's ethical frame

- Test only devices you own or are authorized to test (personal devices,
  SRD-loaned devices, engagement scope).
- Never test against accounts, devices, or services of people who didn't
  consent — including "just to see if it works."
- Findings stay private until coordinated disclosure with the vendor.
- The framework enforces a capability boundary (`SECURITY.md`): no exploit
  deployment, no surveillance, no credential theft, no persistence, no
  sandbox/TCC bypass tooling. Operations outside that boundary fail with
  exit code 5. This is a feature: it keeps your research and your evidence
  inside what Apple's program rules (and the law) expect.

### 6. What this framework is (and is not)

**Is**: a deterministic, resumable research pipeline — corpus management,
coverage-guided and structure-aware fuzzing against real Apple parsers (on
the Mac), crash triage/minimization/dedup, exploitability *indicator*
analysis, on-device confirmation, differential/regression testing, CVE
patch-regression checks, detection-signature authoring, and
report/evidence-pack generation.

**Is not**: an exploit framework, a jailbreak, a C2, or a surveillance
tool. It produces *evidence*, not weapons.

---

## Part II — The framework, component by component

### 7. Architecture in one page

```
ios-research/
├── src/ios_research/          # the framework (Python)
│   ├── targets/               # everything that can execute an input
│   ├── commands/              # CLI command groups (one file per group)
│   └── …                      # engines, stores, analyzers (see §9)
├── tools/
│   ├── harness/               # C harness for real Apple parsers (macOS)
│   ├── campaign/              # libFuzzer campaign runner + device bridge
│   └── mac_campaign/          # CLI-wired campaign engine
├── tests/                     # ~800 deterministic tests, CI-gated
└── research/                  # findings, surface maps, research log
```

**Workspace** (`.ios-research/` by default): every artifact of a session
lives in content-addressed or id-prefixed stores — `corpus/`, `crashes/`,
`analysis/`, `experiments/`, `artifacts/`, `reports/`, `diffs/`. Records are
JSON; inputs are content-addressed blobs (SHA-256). Deleting the workspace
deletes the session; nothing leaks outside it.

**Determinism contract**: a frozen clock and seeded RNGs mean the same
command sequence reproduces byte-identical artifacts. This is what makes
"reproducibility" a testable property rather than an aspiration, and it's
why reports can cite inputs by hash.

**JSON everywhere**: every command accepts `--json` and emits the envelope
`{ok, command, data, messages, error, exit_code}` with stable exit codes
(0 OK, 1 ERROR, 2 USAGE, 3 NOT_FOUND, 4 VALIDATION, 5 SAFETY, 6 INTERRUPTED,
7 STATE). Agents and scripts should consume only this.

### 8. The target model

A *target* is anything that can `execute(bytes) → ExecResult`. Everything
downstream (fuzzer, triage, analysis) is target-agnostic.

| Target family | What it is | When to use |
|---|---|---|
| `mock:parser`, `mock:parser-v2` | In-process Python parsers with planted, *known* bug classes (OOB write, UAF, type confusion) | Pipeline validation, training, differential/regression demos — never evidence |
| `audio:wav/mp3/aac/alac` | Pure-Python format parsers with realistic structure | Fast iteration on mutators/oracles without native builds |
| `mac:imageio/coregraphics/audiotoolbox/coretext` | **Real Apple parsers** via a C harness (ASan+UBSan+libFuzzer) on macOS — ImageIO, CoreGraphics PDF, AudioToolbox, CoreText | Primary discovery engine; code is shared with iOS, so findings transfer (FINDING-04 proved it end-to-end) |
| `mac:selftest` | C harness with three deliberate ASan-detectable bugs (OOB read/write, UAF) keyed on input markers | Validates the entire crash pipeline (parse→dedup→minimize→reproduce) against real sanitizer output |
| Module targets (`wifi:`, `bluetooth:`, `ipc:`, `kernel:`, `pq3:`, `wifiaware:`, `messaging:`, `lockeddevice:`, …) | Structured mock models of iOS subsystems (protocol state machines, IPC surfaces) | Exercising *workflow/orchestration* logic and generating realistic corpora for those domains |
| `jsc:semantic`, `mach:sim` | Semantic JS-engine model; Mach message model (`mach_msg` subset) | Kernel-boundary and engine-logic research planning |
| `custom:*` (target SDK) | Your own target from a manifest + C template, built and registered at runtime | Testing anything with a C API on your Mac (third-party parsers, daemons) |
| On-device (SRD / personal iPhone) | Not a fuzz target — a **confirmation oracle** via the AudioProbe app + `confirm_on_device.py` | Proving a Mac-discovered input reproduces on real hardware |

**The mac harness** (`tools/harness/mac_fuzz_harness.c`): one C file,
compiled per framework (`build.sh [--driver|--libfuzzer] [--trace-cmp]
<target>`). It `dlopen`s the real system framework, feeds the fuzz input
through the same entry an iOS device would use (`CGImageSourceCreateWithData`,
`AudioFileOpenWithCallbacks`, `CTFontManagerCreateFontDescriptorsFromData`,
`CGPDFDocumentCreateWithProvider`), and lets ASan/UBSan catch violations.
Callbacks are textbook-correct (short reads at EOF) — so a hang or crash is
Apple's parser, not an artifact. The FINDING-04 investigation is the worked
example of proving that (stock `afinfo` reproduced the hang).

**Seeds**: `_mac_seeds.py` ships minimal *valid* files per format (PNG/GIF/
BMP/TIFF/ICO, WAV/AIFF, PDF, a synthetic sfnt font builder) plus
**structure-aware mutators** (PNG-aware, sfnt-aware) that mutate fields the
format actually parses. Real-format seeds harvested from the system
(`/System/Library/Fonts/**`, Desktop Pictures, etc.) are what campaigns
should start from (`run_campaign.py` does this automatically).

### 9. Module reference — what each thing does

Grouped by function. (All are `src/ios_research/<name>.py`; CLI groups in
parentheses.)

**Execution & fuzzing**
- `fuzz` (`fuzz`) — deterministic, resumable mutation-based fuzzing engine.
  Batched persistence, crash dedup at record time, mutation weights
  (`mutation`), timeout handling. The loop that everything else feeds.
- `engines` (`engine`) — pluggable execution engines; libFuzzer campaigns are
  one engine, the in-process loop another.
- `directed` — AFLGo-lineage *directed* greybox fuzzing: scores seeds by
  distance to target code points (call-graph distances) so the fuzzer
  gravitates toward a chosen function instead of exploring uniformly.
- `grammar` — versioned grammar-aware mutator plugins: when byte mutation
  can't reach a protocol's deep states, a grammar plugin generates
  structurally valid (then subtly invalid) messages.
- `llmmutate` — LLM-in-the-loop mutation: an LLM proposes inputs guided by
  crash feedback; proposals are ingested as candidates, never auto-trusted.
- `dictionary` — libFuzzer token dictionaries per format (magic bytes,
  chunk names, section tags) so coverage guidance can jump format gates.
- `stateful` — stateful workflow fuzzer: models sequences of authorized
  app/API operations as a state machine and fuzzes *transitions*, for
  logic bugs that no single input can trigger.
- `races` — TSan report ingestion + scheduling-perturbation hooks for
  concurrency findings.
- `harness_runner`, `harness` — build/run plumbing for the C harness,
  isolated child-process execution for generated harness candidates.

**Data management**
- `corpus` (`corpus`) — corpus create/import/dedupe/minimize; the corpus is
  the fuzzer's memory. Dedupe by execution signature, minimize by coverage.
- `artifacts` — content-addressed blob store (SHA-256); every crash input is
  here forever, referenced by hash.
- `crashes` (`crash`) — crash record store with signature-based dedup,
  reproduce, minimize (ddmin), compare. Signatures are deterministic
  (sanitizer class + site hash), so the same bug found twice is one record
  with `count` incremented.
- `experiment` (`experiment`) — experiment records: target, seed, params,
  stats. The unit of provenance for a campaign.
- `workspace`, `config`, `hashing`, `ids`, `clock`, `errors`, `safety` — the
  substrate: path containment (no escaping the workspace), config hashing,
  id minting, the frozen clock, the error taxonomy, the safety gate.

**Analysis & evidence**
- `sanitizers` — parse ASan/UBSan/TSan reports into normalized diagnostics
  (classification, faulting address, stack) and derive stable signatures.
- `analysis` (`analyze`, `analysis`) — evidence-gated exploitability
  *indicators*: maps sanitizer class + register/fault evidence to a
  classification (`CRASH_ONLY` → `CONTROLLED_MEMORY_ACCESS_INDICATOR` →
  `CODE_EXECUTION_INDICATOR`) with explicit confidence and open questions.
  Never fabricates code-exec claims — the report layer rejects overclaims.
- `targetflags` + `flagcapture` (`targetflags`) — Apple's Target Flag
  taxonomy (commpage words proving register control / arbitrary RW / PC
  control) and detection of flag captures in crash evidence. This is the
  bridge between "we have a crash" and "we can claim a bounty tier."
- `mitigation` — records the memory-safety mitigation generation of the
  research device (MIE/EMTE/PAC era), which bounds what outcomes are
  demonstrable (§2.4).
- `evidence` (`evidence`), `report` (`report`) — evidence tracing and report
  generation with validation that rejects missing evidence, overclaims, and
  forbidden content. The output is a disclosure-ready markdown report.
- `bounty` — submission-readiness checks: does the evidence pack satisfy the
  bounty category's demonstration mechanics?
- `triage` — crash triage pipeline orchestration (classify → minimize →
  reproduce → compare).

**Cross-checking & regression**
- `differential` (`diff`, `beta`) — differential testing: run the same input
  against two builds/targets, rank outcome transitions, detect regressions
  (`beta diff` for release pairs, lockdown pairs via `lockdown`).
- `cvereg` (`cve`) — CVE registry: record known CVEs with trigger inputs and
  expected signatures; `cve validate` re-runs them against a build to prove
  patches didn't regress (or that a "patched" device is vulnerable again).
- `advisories` (`advisory`) — import public Apple advisories, cross-reference
  your findings, score novelty (is what you found already public?).
- `ipswdiff` (`nday`) — IPSW build-to-build symbol patch-diffing: diff two
  firmware images' symbol tables to find *what a patch actually changed*,
  prioritized by reachability — the starting point for n-day reproduction.
- `detection` (`detect`) — deterministic YARA-style rule engine over samples
  you supply: author detection signatures for defensive validation (also
  proves your finding is detectable, which strengthens reports).

**Platform & device**
- `devices`, `vdevices`, `lockeddevice` (`device`, `lockeddevice`) — device
  registry (mock, SRD-backed, locked-device profiles).
- `srd` — Apple Security Research Device backend: strictly opt-in, refuses
  to start without explicit approval data (exit 5). SRDs are Apple-loaned
  devices where research is contractually expected.
- `xcode` (`xcode`) — Xcode test-plan adapter: run XCTests as targets,
  ingest XCResult diagnostics — brings UI/app-layer test results into the
  same evidence pipeline.
- `targetsdk` — the custom-target SDK: manifest + template → build →
  register → execute, for testing anything with a C API on your Mac.
- `surface` (`surface`) — attack-surface inventory ingest and bounty-EV
  campaign planning (the code behind the attack-surface map).
- `campaign_sync` (`campaign`) — distributed corpus synchronization via
  safe exchange bundles (fuzz across machines without sharing raw
  untrusted state).
- `supply` (`supply`) — offline dependency vetting: requirements audit,
  behavior scan, lockfile drift verify. You are a target too.
- `coverage`, `coverage_report`, `observability`, `logging_util` — sancov
  adapters, coverage reporting, structured logging with secret redaction.

**Research orchestration**
- `research` (`research`) — the 12-stage end-to-end orchestration
  (init → corpus → fuzz → triage → analyze → … → report) with
  pause/resume equivalence and resource limits.
- `agent` (`agent`) — the machine-readable agent interface: schema
  introspection, bounded end-to-end runs, environment status.
- `matrix` (`matrix`), `suites`, `findings`, `spoints`, `oracles`,
  `macoracles`, `nettransport`, `proximity`, `machmsg` — experiment
  matrices, suite catalogs, finding records, search-point experiments,
  metamorphic oracles (non-crash bug detection), transport/proximity
  research models.

**Tools directory**
- `tools/harness/` — the C harness + `build.sh` (driver vs libFuzzer modes,
  sanitizer profiles, trace-cmp).
- `tools/campaign/run_campaign.py` — the long-haul libFuzzer campaign
  runner: harvests real-format seeds from the system, per-target
  dictionaries, persistent corpora across rounds (coverage compounds),
  value-profile option, records crashes/hangs into the store per round.
- `tools/campaign/confirm_on_device.py` + `device_probe/` — the on-device
  confirmation bridge (§15).
- `tools/mac_campaign/run.py` — the CLI-wired campaign engine
  (`campaign` command group).
- `tools/experiment_loop/` — closed-loop experiment environments (knob →
  metric) for measuring technique changes (mutation weights, directed
  fuzzing) rather than finding bugs.

---

## Part III — Methodology

### 10. The testing lifecycle

```
   ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
   │ 1 RECON    │→  │ 2 PRIORIT- │→  │ 3 HARNESS  │→  │ 4 FUZZ     │
   │ surface    │   │ IZE (EV)   │   │ & seed     │   │ (rounds)   │
   └────────────┘   └────────────┘   └────────────┘   └─────┬──────┘
                                                            │
   ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────▼───────┐
   │ 8 REPORT & │←  │ 7 ANALYZE  │←  │ 6 CONFIRM  │←  │ 5 TRIAGE   │
   │ DISCLOSE   │   │ & evidence │   │ on device  │   │ & minimize │
   └────────────┘   └────────────┘   └────────────┘   └────────────┘
```

**1. Recon.** Enumerate the input formats and daemons of your chosen surface.
For each: what process parses it, at what privilege, with what reachability
(zero-click? one-click? proximity?). The attack-surface map is the starting
census; `surface ingest` turns a device snapshot into a working inventory.

**2. Prioritize.** Score EV (§4). Pick 1–2 surfaces per campaign; breadth
without depth finds nothing. Check `advisory scan` first — don't rediscover
public bugs (and do check whether the *fix* is complete; patch-regression is
a valid finding class, see `cve`/`nday`).

**3. Harness & seed.** Get *valid* inputs first: harvest real files from the
OS (`run_campaign.py` does this), verify they parse cleanly, then let
mutation explore around them. A corpus of garbage finds nothing; a corpus of
valid files with a coverage-guided mutator finds the parser's edge cases.

**4. Fuzz.** Long, round-compounding campaigns with persistent corpora
(coverage accumulates across rounds), dictionaries for format gates, value
profile for comparison-heavy parsers. Run overnight; check the corpus growth
rate — a stagnant corpus means the mutator can't get past a format check
(fix the dictionary or add a structure-aware mutator, don't just wait).

**5. Triage.** Every crash: dedup by signature → minimize (ddmin) →
reproduce → classify. The framework does all four; your job is the judgment
calls: is this the harness's own bug? (selftest markers, harness code in the
stack) Is this a *known* bug? (`advisory match`) Is it memory-safety or
resource class?

**6. Confirm on device.** Mac findings transfer at a high rate but *must* be
confirmed before they're evidence: `confirm_on_device.py --crash <id>`.
A `HANG` verdict on device confirms liveness; a crash on device with an ASan
report confirms memory safety. Record device generation (`mitigation`).

**7. Analyze & evidence.** `analyze` produces exploitability *indicators*
with explicit confidence; `targetflags`/`flagcapture` check whether the
crash demonstrates a Target-Flag primitive; `bounty` checks
submission-readiness against the category's demonstration mechanics.

**8. Report & disclose.** §16. Then feed the finding back: add it to the
regression corpus (`cve add` or the regression suite) so future builds are
checked against it.

### 11. Techniques in depth

#### 11.1 Coverage-guided fuzzing (the workhorse)

libFuzzer's in-process loop: mutate → execute → observe coverage counters →
keep inputs that reach new states. What matters in practice:

- **Persistent corpora across rounds** — coverage compounds. A single 8-hour
  run explores less than 12 × 40-min rounds with a shared corpus, because
  each round restarts from everything the last one learned.
- **Dictionaries** beat brute force at format gates: a parser that checks
  for `"ftyp"` before parsing will never be reached by random bytes, but one
  dictionary token jumps straight past it. Ship a dictionary per format
  (the campaign runner does).
- **Value profile** (`-use_value_profile=1`) instruments comparisons and
  feeds the observed values back to mutation — slow per-exec, but it cracks
  magic-number checks (`version == 2`) that neither coverage nor
  dictionaries reach. Use it when corpus growth stalls.
- **Fork mode** (`-fork=N`) isolates worker crashes so one crashing input
  doesn't kill the campaign — the default for long campaigns.
- **Reading the signs**: growing corpus = healthy; stagnant corpus = a
  format gate the mutator can't pass (fix seeds/dictionary/structure
  mutator); many `slow-unit`s = near-hang territory (harvest them — FINDING-04
  came from a timeout artifact); `oom-` artifacts = memory-amplification
  candidates (resource-class, but document them).

#### 11.2 Structure-aware mutation

Byte-level mutation wastes 99% of cycles on inputs rejected by the first
header check. Structure-aware mutators speak the format: the framework's
PNG mutator edits chunk lengths/types (keeping the CRC game interesting),
the sfnt mutator perturbs table-directory offset/length pairs — targeting
*offset math*, where font-parser bugs historically live. Write one per
format you seriously hunt; register it in `_mac_seeds.structure_mutate`;
unit-test it for determinism and for the "corrupted input must not crash
the mutator itself" case (we shipped an overflow fix for exactly this).

#### 11.3 Static-analysis scouting

The scout answers *where to aim*; fuzzers confirm *what's real*. Pure static
vuln-finding drowns in false positives — the hybrid is the proven pattern:

- **Surface census** (`staticscan scan`) — symbols, linked libraries, and
  constant strings from any Mach-O, or directly from the dyld shared cache
  (constant strings are stored contiguously, so fingerprinting needs no
  extraction).
- **Parser fingerprinting** (`staticscan fingerprint`) — match format
  constants (`"ID3"`, `"ftyp"`, sfnt tags, PNG chunk names) against the
  binary's strings to prove which parser families it contains, with
  per-token hit counts as evidence.
- **Evidence-backed dictionaries** (`staticscan dict`) — the matched
  constants rendered as a libFuzzer dictionary: the *exact bytes the binary
  compares*, not guessed magics. Feed straight into the campaign runner.
- **Directed-fuzzing targets** (`staticscan callgraph --focus`) — normalize
  a Ghidra headless export (`tools/staticscan/ghidra_export.py`) into the
  call-graph document `directed.load_callgraph()` consumes, and identify
  *parser focus functions*: functions that reference format constants.
  Walking the call graph toward those functions reaches deep parser states
  in hours instead of weeks.

Platform note: system framework paths are broken symlinks on cryptex-era
OSes; the code lives in the dyld shared cache
(`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`). `staticscan
locate <framework>` reports which case you're in. Ghidra analysis requires
extracting the dylib of interest from the cache first (dyld_shared_cache_util
or the `ipsw` tool); strings-based fingerprinting works on the cache as-is.

RE of Apple binaries for vulnerability research on your own devices is the
activity the Apple Security Bounty program contemplates — this module stays
inside that line: it produces targets and maps, never exploit material.

#### 11.4 Directed fuzzing

When you know *where* the bug should be (a function identified by patch
diffing, a newly added parser), directed greybox fuzzing scores inputs by
call-graph distance to the target and prefers low-distance seeds — reaching
deep code in hours instead of weeks. Use after `nday` patch-diffing points
you at a changed function.

#### 11.5 Grammar & stateful (protocol) testing

Parsers of *sequences* (messaging protocols, pairing handoffs, sync
engines) don't crash on single inputs; they crash on *state transitions*.
Two tools: grammar plugins (generate valid-then-invalid messages per a
versioned grammar) and the stateful workflow fuzzer (model the protocol as
a state machine, fuzz the transitions). The module targets (`pq3:`,
`wifiaware:`, `messaging:`) exist to develop and validate these workflows
against realistic models before aiming them at real transports.

#### 11.6 LLM-in-the-loop mutation

An LLM reads the format spec (or the crash history) and proposes inputs;
proposals are ingested as *candidates* into the normal coverage-guided loop
— never auto-trusted, always measured. Useful for semantic fields no
dictionary covers ("make this length field *just barely* inconsistent with
the chunk size"). The `llmmutate` module tracks proposal provenance and
whether each proposal actually contributed coverage or crashes.

#### 11.7 Differential & regression testing

Run identical inputs against two builds (or two configurations) and compare
outcomes. Outcome *transitions* (crash→clean = fixed; clean→crash =
regressed) are the signal. This finds logic bugs no fuzzer targets, and it's
the honest way to test *mitigations*: `beta diff` for release pairs,
`lockdown` for Lockdown-Mode pairs (the +100% bonus tier). Determinism
makes the comparisons exact rather than statistical.

#### 11.8 N-day reproduction and patch-diffing

`nday` diffs two IPSW builds' symbols: functions changed between builds are
the patch's fingerprint. Prioritized by reachability, that list is a
hunting map: fuzz the *changed* functions of the *previous* build to
reproduce the patched bug (validates the fix, feeds `cve validate`) — or
find that the patch was incomplete, which is a legitimate, often
under-reported finding class.

#### 11.9 Concurrency (races)

TSan on the harness builds + scheduling perturbation hooks (`races`):
fuzz with randomized scheduling to shake out TOCTOU and double-visit bugs
that deterministic single-threaded runs never see. Race findings need
special care in reports (reproducibility is statistical; document the
perturbation schedule).

#### 11.10 Oracles for non-crash bugs

Not all bugs crash: wrong parsing results, silent data corruption,
authorization bypasses. Metamorphic oracles (`oracles`, `macoracles`)
assert *properties* ("parsing then re-serializing is identity",
"authorization decision depends only on the entitlement, not the
connection order") and flag violations — the only practical way to hunt
logic bugs at scale.

#### 11.11 Supply-chain vetting

Your research box is itself a target: `supply audit/scan/verify` checks
declared vs installed dependencies, scans for behavior drift, and verifies
lockfiles. Run it before handling any third-party corpus or target.

### 12. What each *test* does (the suite taxonomy)

The ~800-test suite is itself documentation of expected behavior:

| Suite | What it pins down |
|---|---|
| `test_foundation` | exit codes, hashing, ids, config, safety gate, workspace containment |
| `test_cli_runtime` | init/config/device/target/experiment lifecycle, artifact store |
| `test_corpus_fuzz` | mutation determinism, corpus ops, crash dedup, resume-equivalence |
| `test_audio_module`, per-module tests | each mock target's parser behavior + diagnostics |
| `test_crash_triage` | ddmin, reproduce, classify, compare, regression corpus replay |
| `test_analysis` | evidence-gated exploitability indicators; **never fabricates code-exec** |
| `test_differential` | v1/v2 transitions, regression direction, diff reproducibility |
| `test_agent` | schema contract, JSON envelope, determinism |
| `test_report` | section generation, evidence tracing, rejection of overclaims |
| `test_research` | 12-stage orchestration, resume equivalence, resource limits |
| `test_integration_cli` | end-to-end artifact chain through the real CLI |
| `test_regression` | known inputs still crash with recorded signatures |
| `test_mutation_weights`, `test_fuzz_throughput` | technique changes measured, not vibes |
| `test_detection` | YARA-style engine + detect CLI |
| `test_cvereg` | CVE registry CRUD + deterministic validation |
| `test_workspace_containment` | paths can't escape the workspace; symlink attacks rejected |
| `test_harness_isolation` | generated harnesses run in isolated children |
| `test_mac_target` | real-harness behavior: ASan parsing, libFuzzer integration, timeout accounting |
| `test_device_confirm` | device bridge: magic dispatch mirrors the ObjC probe, verdict matrix |
| `test_targetsdk` | custom-target manifest → build → register → execute |

`native`-marked tests (real ASan harness builds, device runs) are opt-in and
deselected in CI; everything else is deterministic and runs on every PR.

---

## Part IV — When you find something

### 13. Triage: the first hour

1. **Is it real?** Re-run the minimized input on a fresh process
   (`crash reproduce`). Check the stack: if frames point into
   `mac_fuzz_harness.c` or the selftest markers (`OOB`/`WRT`/`UAF`), it's
   your harness, not Apple.
2. **What class?** ASan/UBSan classification (heap-buffer-overflow,
   use-after-free, SEGV on unknown, UBSan misbehavior…) → the framework
   normalizes this into `classification` + a stable `signature`.
3. **Is it known?** `advisory match` against imported advisories; check the
   regression corpus. Known ≠ worthless — a *regression* of a fixed bug is
   valuable, a rediscovery of a public bug is not reportable.
4. **Minimize.** ddmin to the smallest input preserving the signature
   (`crash minimize`). Small inputs get triaged faster by the vendor and
   make the root cause obvious. FINDING-04 went 41 → 24 bytes, which is
   what made the exact-10-byte-distance mechanism visible.
5. **Record provenance.** Experiment, seed, corpus lineage, harness build
   hash, device generation. Reports without provenance are guesses.

### 14. Exploitability analysis: from crash to claim

The gap between "it crashed" and "it's a $X finding" is *control*. Work the
ladder, honestly, with evidence at each rung:

1. **Crash only** — process dies, no controlled state. (DoS class.)
2. **Controlled memory access indicator** — faulting address/registers
   correlate with input bytes (e.g., fault address = value from the input).
   The analyzer flags this with `CONTROLLED_MEMORY_ACCESS_INDICATOR`.
3. **Register control / arbitrary R/W** — demonstrable via Apple's Target
   Flags: crash logs whose registers/fault addresses carry the commpage
   ASB target values prove 32/64-bit register control or arbitrary
   read/write. `flagcapture` detects these captures in stored evidence;
   `targetflags` maps them to the taxonomy and to bounty tiers.
4. **Code execution** — PC control with a controlled target, or sandbox
   escape. The analyzer only reaches `CODE_EXECUTION_INDICATOR` with
   explicit register/PC evidence; the report layer *rejects* overclaims.

Also assess: **reachability** (what input path delivers this — zero-click?
one-click? local?), **mitigation generation** (EMTE changes demonstrability),
and **containment** (parser-daemon separation means crash ≠ compromise —
argue the path, don't assert it).

### 15. Device confirmation (the evidence multiplier)

A Mac finding is a *lead*; hardware confirmation makes it *evidence*:

```bash
# one command, from crash store to iPhone verdict:
.venv/bin/python tools/campaign/confirm_on_device.py --crash crash_XYZ
# → {"verdict": "HANG"|"OPEN_OK"|"OPEN_FAIL"|"ERROR", "device": ..., "os_version": ...}
```

The AudioProbe app sniffs the input's magic bytes and routes it through the
matching framework API on-device (ImageIO / CoreGraphics / CoreText /
AudioToolbox), logging `PROBE` verdicts captured over the CoreDevice tunnel.
A `HANG` verdict confirms a liveness bug on hardware (FINDING-04); a device
crash with a sysdiagnose-able report confirms memory safety. Always run the
negative control (a benign file of the same format) in the same session —
an uncontrolled experiment is not evidence.

Setup (one-time): Xcode signing with a personal team, Developer Mode on the
phone, trust the developer cert — full steps in
`tools/campaign/device_probe/README.md`.

### 16. Reporting and disclosure

**Write-up structure** (the `report` command generates the skeleton; the
FINDING-04 document is a worked example):

1. **Executive summary** — one paragraph a triager can act on.
2. **Impact** — reachability-qualified severity; honest about class (DoS ≠
   RCE). Overclaiming is the #1 reason reports get deprioritized.
3. **Reproduction** — the *smallest* command sequence, ideally copy-paste
   (`printf … | xxd -r -p > file; afinfo file`). Ten-second reproduction
   gets triaged; hour-long setups don't.
4. **Technical details** — sampled stacks, input structure, root-cause
   hypothesis (labeled as hypothesis unless you can prove it).
5. **Affected versions & platforms** — every OS/hardware pair you actually
   tested, including negatives.
6. **Disclosure intent** — unpublished, coordinating, no publication before
   resolution.

**The Apple process**: submit to product-security@apple.com; expect an
auto-acknowledgment with a tracking ID; triage takes weeks (months is
normal); fixes ship in point releases; credit appears in the advisory's
acknowledgements page. Apple may award bounty at its sole discretion per
the published category table — DoS-class findings are acknowledged, not
paid (§3). Ask for a timeline in your first reply; follow up politely if
silenced past it.

**Do not**: publish before the fix ships, share with third parties, sell to
brokers, or test the fix on other people's devices. The framework's safety
gate and report validation exist to keep you inside these lines.

---

## Part V — Trending & emerging

### 17. Emerging attack surfaces (as of 2026)

- **PQ3 (post-quantum iMessage ratchet)** — new cryptographic state machine
  in the message path; protocol state-machine logic is the bug class, and
  it's zero-click reachable. (`pq3:` module models it.)
- **Wi-Fi Aware (iOS 26)** — brand-new discovery + dataport stack, proximity
  reachable, least-audited code in the fleet. (`wifiaware:` module.)
- **RCS support** — a new message-transport decoder beside SMS/MMS/iMessage;
  new parsers in the zero-click path.
- **Apple Intelligence pipelines** — on-device models + Private Cloud
  Compute: new input formats (prompts, context payloads), new IPC
  boundaries, and the PCC attestation bounty category ($100K–$1M).
- **Lockdown Mode differentials** — every LM bypass is +100%; the
  differential-testing workflow (`lockdown`) is the systematic approach.
- **USB-C era / sideloading (EU)** — new install paths and new policy
  enforcement code = new logic-bug surface.
- **Custom app marketplaces & browser engines (EU DMA)** — non-WebKit
  engines and marketplace notarization are new trust boundaries.

### 18. Emerging mitigations and what they mean for testing

- **EMTE everywhere** — memory bugs become immediate faults: discovery gets
  easier, exploitation gets harder. Stratify devices by generation; a bug
  may be a strong primitive on A15 and a clean crash on A17.
- **MIE kernel partitions** — cross-partition heap corruption is dead;
  type-confusion and logic bugs in kernel code are not.
- **Parser separation spreading** — more zero-click parsers move into
  sandboxed daemons; crash-based evidence needs reachability arguments.
- **PCC** — attestation-based cloud compute: the bug class shifts to the
  *protocol* (attestation logic, request routing) rather than memory.

### 19. Trending techniques

- **Chain-first hunting**: pick the chain tail first (a kernel userclient
  or XPC endpoint with known weak neighbors), then hunt the entry bug that
  reaches it — the bounty tiers pay for chains, so plan backwards from the
  demonstration.
- **Kernel fuzzing via IOKit user clients** from a Mac (shared XNU) with
  `machmsg`-modeled messages; DriverKit raises the bar but shrinks the
  attack surface.
- **Baseband research** remains the zero-click crown jewels but requires
  dedicated radio labs — out of scope for this framework, watch the SRD
  program's expansions.
- **Corpus distillation across campaigns** (`campaign sync`): multiple
  machines, merged corpora via safe exchange bundles — coverage compounds
  across researchers without sharing untrusted state.
- **Measurement-driven technique selection**: before adopting a mutator or
  strategy, measure it in the experiment loop (the repo's own history:
  weight retuning +27% exec/s, directed fuzzing, LLM proposals — all
  measured, some negative results kept honestly).

---

## Appendix A — Quick reference

```bash
# environment
ios-research agent status --json          # readiness + workspace counts
ios-research target list --json           # registered targets
ios-research agent inspect --json         # full machine-readable CLI schema

# discovery (long-haul, real parsers)
tools/harness/build.sh --libfuzzer imageio coregraphics audiotoolbox coretext
.venv/bin/python tools/campaign/run_campaign.py --target coretext \
    --experiment exp_X --duration 2400 --workers 4 --rounds 12 \
    --value-profile

# triage
ios-research crash list --json
ios-research crash minimize crash_XYZ --json
ios-research crash reproduce crash_XYZ --json
ios-research analyze crash_XYZ --json

# device confirmation
.venv/bin/python tools/campaign/confirm_on_device.py --crash crash_XYZ

# cross-checks
ios-research advisory scan --json         # is this already public?
ios-research cve validate --json          # did a patch regress?
ios-research detect scan FILE --json      # detection signature check

# reporting
ios-research report create crash_XYZ --json
ios-research bounty readiness --json      # submission-readiness check
```

## Appendix B — Reading the signs (campaign health)

| Signal | Meaning | Action |
|---|---|---|
| corpus growing steadily | healthy exploration | keep running |
| corpus stagnant | format gate blocking mutation | add dictionary tokens / structure mutator / better seeds |
| many `slow-unit-` artifacts | near-hang territory | harvest & minimize them (FINDING-04 came from one) |
| `oom-` artifacts | memory amplification | resource-class; document, don't expect bounty |
| `timeout-` artifacts | hang candidates | re-run with a longer budget; confirm on device |
| `crash-` artifacts | the actual quarry | triage immediately (§13) |
| `runs=0` or stats unparsed | stats-line format drift | campaign still valid; stats cosmetic |

---

*Authorized research only. See [SECURITY.md](../SECURITY.md) for the
capability boundary and [ATTACK-SURFACE-MAP.md](../research/ATTACK-SURFACE-MAP.md)
for the prioritized surface inventory.*

# macOS In-Process Fuzzing (real crashes, no device)

Every *mock* target in `ios-research` decides "crashes" with `if` statements and
synthesizes diagnostics from `sha256(input)` (`targets/diagnostics.py`). The
pipeline (fuzz → triage → minimize → analyze → differential → report) is real,
but until now it never operated on a **real** crash.

The `mac:<framework>` targets change that. Many iOS parsing libraries ship the
**same binaries on macOS** (ImageIO, CoreGraphics, AudioToolbox, …). A native
`-fsanitize=fuzzer,address,undefined` harness `dlopen`s the framework, calls a
real decode entry point, and — when the sanitizer catches a defect — emits a
report with a **real faulting address, registers, stack, and modules**. The
target normalizes that report into the same `Diagnostics` the rest of the
pipeline already consumes. No iPhone required.

> **Authorized / own-machine research only.** The harness only feeds bytes to a
> parsing entry point in a framework already installed on your machine. It does
> not bypass permissions or access device sensors. Real findings route to the
> **Apple Security Bounty** via responsible disclosure. See `SECURITY.md`.

## Why this is the productive real-signal path

- No device restrictions, full sanitizer instrumentation.
- Real faulting addresses make the exploitability/controllability analysis
  meaningful (it currently measures a hash on the mock path).
- The methodology already validated against the mock (field perturbation,
  avalanche/targeting, ddmin minimization, differential triage) starts
  operating on genuine data — **no pipeline changes** downstream of `execute()`.

## Requirements (opt-in; CI stays mock-only)

Two build modes (see below). The **default driver mode** needs only ASan/UBSan,
which the Apple toolchain provides — but note:

- The **Command Line Tools** clang's ASan runtime CHECK-fails
  (`asan_init_is_running`) when the harness `dlopen`s a system framework. Use a
  **full Xcode** clang (or Homebrew LLVM). `build.sh` auto-selects the active
  toolchain's clang via `xcrun` and warns when Command Line Tools is active:
  ```bash
  sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
  ```
- **libFuzzer mode** additionally requires `libclang_rt.fuzzer_osx.a`, which
  **Apple ships in neither the Command Line Tools nor full Xcode**. Install an
  open-source LLVM for it: `brew install llvm`.

The `mac:<framework>` factories are always registered (cheap), but a target is
only `available` once its harness binary is built. CI never builds or runs them.

## Build the harness

```bash
# default: standalone ASan/UBSan driver — works on the stock Apple (Xcode) clang
tools/harness/build.sh imageio
tools/harness/build.sh all

# libFuzzer mode (needs a fuzzer-capable clang, e.g. Homebrew LLVM)
CC=$(brew --prefix llvm)/bin/clang tools/harness/build.sh --libfuzzer imageio
```

Output: `tools/harness/build/<framework>_fuzzer`. The target auto-discovers that
path. To point elsewhere:

```bash
export IOS_RESEARCH_MAC_HARNESS=/path/to/imageio_fuzzer
```

Available framework keys and their entry points:

| target id           | framework      | entry point                        |
|---------------------|----------------|------------------------------------|
| `mac:imageio`       | ImageIO        | `CGImageSourceCreateWithData`      |
| `mac:audiotoolbox`  | AudioToolbox   | `AudioFileOpenWithCallbacks`       |
| `mac:coregraphics`  | CoreGraphics   | `CGPDFDocumentCreateWithProvider` + page render |
| `mac:selftest`      | (none)         | controlled buggy parser — see below |

### Self-test target (real-crash pipeline validation)

`mac:selftest` is a tiny, intentionally-buggy in-process parser with **no
framework dlopen** — it deliberately triggers three real ASan/UBSan findings
(`OOB` → heap OOB read, `WRT` → heap OOB write, `UAF` → use-after-free) on a byte
marker. It exists to validate the whole real-crash path end-to-end (fuzz → real
ASan → parse → dedup → minimize → reproduce), which hardened frameworks rarely
exercise in a short run. It builds on **any** macOS clang (no dlopen), so it also
serves as a toolchain smoke test.

```bash
tools/harness/build.sh selftest
IOS_RESEARCH_MAC_HARNESS=$PWD/tools/harness/build/selftest_fuzzer \
  ios-research fuzz start --target mac:selftest --max-cases 200
# -> 3 unique real crashes; crash reproduce re-triggers; crash minimize (ddmin)
#    shrinks a 200-byte input to the 3-byte marker with the signature preserved.
```

### Build modes

| mode | flags | main() | toolchain |
|------|-------|--------|-----------|
| `--driver` (default) | `-fsanitize=address,undefined -DHARNESS_STANDALONE` | built into the harness | stock Apple (full-Xcode) clang |
| `--libfuzzer` | `-fsanitize=fuzzer,address,undefined` | supplied by libFuzzer | LLVM/clang with the fuzzer runtime |

The standalone driver accepts **one or more** input files and speaks a tiny
stdout protocol (`RUN <i>` / `DONE <i> decoded|rejected`) so the Python target
can recover per-input outcome and attribute a crash within a batch.

### Optional SanitizerCoverage feedback

Driver builds also enable clang's `-fsanitize-coverage=trace-pc-guard`.
For each single-input CLI-engine execution, the driver writes the guards hit
inside the target call to a local temporary map; `MacFuzzTarget` imports that
map as stable `sancov:mac:<target>:guard:<n>` feature IDs. The generic fuzz
engine retains inputs that add a new guard and records the evidence in the
corpus manifest. This works only for a compatible driver build; a missing or
empty map falls back safely to the pre-existing deterministic schedule. Guard
IDs are build-specific performance signals, not source locations or a claim of
coverage across an iOS device.

## Run it

### Campaign runner (recommended)

```bash
# out-of-process driver engine (default driver build):
python tools/mac_campaign/run.py --target mac:imageio --cases 20000 \
    --batch 512 --workers 0 --save-crashes /tmp/crashes

# in-process libFuzzer engine (auto-selected for --libfuzzer builds):
python tools/mac_campaign/run.py --target mac:imageio \
    --runs 2000000 --max-total-time 60 --workers 6 --save-crashes /tmp/crashes
```

The runner picks an **engine** (`--engine auto|driver|libfuzzer`):

- **`driver`** (out-of-process): seeds from the target's format-aware seeds,
  mutates with the shared engine, and drives inputs in **batches** across
  **parallel worker processes**. `--batch` sets inputs per process (default 256);
  `--workers 0` auto-picks a capped worker count (see Throughput).
- **`libfuzzer`** (in-process persistent): hands the seeds to libFuzzer, which
  mutates and executes **in-process** with `-fork` workers, collects crash
  artifacts, and re-runs each unique one to normalize its ASan report. `--runs`
  and `--max-total-time` bound it. Auto-selected when the built harness is a
  libFuzzer binary.

Either way it is a real-signal *campaign*, deliberately **not** an experiment-loop
environment (see below).

### Through the CLI pipeline

```bash
ios-research target show mac:imageio               # available=true once built
ios-research fuzz start --target mac:imageio --corpus <dir>
ios-research crash reproduce <crash-id>            # re-trigger the real crash
ios-research crash minimize <crash-id>             # ddmin, signature preserved
ios-research crash analyze <crash-id>              # exploitability on a real address
```

## How the target maps outcomes

`MacFuzzTarget` runs `<harness> <file>` (single) or `<harness> <file> …` (batch)
and maps the result:

| harness result                                     | `Outcome`  |
|----------------------------------------------------|------------|
| exit `0`, stdout `DONE <i> decoded`                | `ACCEPTED` |
| exit `0`, stdout `DONE <i> rejected`               | `REJECTED` |
| exit `0`, no per-input marker (libFuzzer build)    | `ACCEPTED` |
| non-zero **with** a recognizable ASan/UBSan report | `CRASH` (+ normalized `Diagnostics`) |
| non-zero **without** a report                      | `ABNORMAL` |
| exceeds the time budget                            | `TIMEOUT`  |
| harness not built / not found                      | `ABNORMAL` (with a build hint) |

The `decoded` vs `rejected` distinction matters: on a decode target most
malformed inputs are *rejected* by the framework (entry point returns `NULL`),
not decoded — collapsing both to `ACCEPTED` would erase useful corpus signal.

`ASAN_OPTIONS=abort_on_error=0:exitcode=99:detect_leaks=0` keeps a full report on
stderr for parsing. The parser (`targets/asan.py`) is defensive: symbolication
varies by OS build, so every field is optional and an unrecognized report still
yields a usable `Diagnostics` with a stable `asan_…` signature keyed on the
classification and top frames (so dedup groups matching crashes despite jittering
addresses).

## Throughput

Two multipliers compound (measured on `mac:imageio`, Xcode 26.6, 24-core):

1. **Batching** — the driver amortizes process spawn + `dlopen` over many inputs:
   ~16 exec/s (one-process-per-input) → ~4000 exec/s at `--batch 1000`.
2. **Parallel workers** — batches run concurrently across cores
   (`execute_batch` spawns a subprocess and releases the GIL): another ~2.6×.

Combined: **~8800 exec/s** at `--batch 512 --workers 6` — roughly a **550×**
improvement over the naive path. Parallel scaling **plateaus at ~4–6 workers** and
regresses beyond that (many concurrent ASan processes contend for memory and the
scheduler), so `--workers 0` caps the auto default at 6. This is the practical
ceiling for the **out-of-process driver** engine.

When a crash occurs mid-batch the driver re-runs that batch input-by-input so each
crash is precisely attributed (so crash-heavy runs trade throughput for accuracy).

### Beyond the ceiling: the libFuzzer engine

To exceed the out-of-process ceiling, build with `--libfuzzer` and run the
**in-process** engine (`--engine libfuzzer`, auto-selected). libFuzzer executes
`LLVMFuzzerTestOneInput` in-process with no per-input process/`dlopen` cost —
typically 10⁴–10⁵ exec/s — and `-fork` gives parallelism and crash-tolerance in
one. It needs a fuzzer-capable clang (Homebrew LLVM; Apple ships none). The crash
path is identical: each artifact is re-run once and normalized through
`targets/asan.py`.

## Relationship to experiment-loop

`tools/experiment_loop/` optimizes fuzzing *strategy knobs* against deterministic
**mock** metrics — it climbs a knob→metric gradient. Native fuzzing has no honest
such gradient (real crashes are non-deterministic), so there is intentionally
**no `mac_*` experiment-loop environment** (that would violate the repo's
"no gameable knobs" principle). Mac-fuzzing is instead a real-signal **campaign**
run via `tools/mac_campaign/run.py`; a zero-crash run against a hardened
framework is a legitimate negative result to record.

## Determinism

Follow `RESEARCH-DEVICE.md`: experiments already record the OS build and a config
hash; always `crash reproduce` to confirm a crash re-triggers before triage and
reporting. Native crashes are less perfectly deterministic than the mock path —
the signature is intentionally address-independent so reproductions still group.

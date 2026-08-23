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
| `mac:coregraphics`  | CoreGraphics   | `CGDataProviderCreateWithCFData`   |

### Build modes

| mode | flags | main() | toolchain |
|------|-------|--------|-----------|
| `--driver` (default) | `-fsanitize=address,undefined -DHARNESS_STANDALONE` | built into the harness | stock Apple (full-Xcode) clang |
| `--libfuzzer` | `-fsanitize=fuzzer,address,undefined` | supplied by libFuzzer | LLVM/clang with the fuzzer runtime |

The standalone driver accepts **one or more** input files and speaks a tiny
stdout protocol (`RUN <i>` / `DONE <i> decoded|rejected`) so the Python target
can recover per-input outcome and attribute a crash within a batch.

## Run it

### Campaign runner (recommended)

```bash
python tools/mac_campaign/run.py --target mac:imageio --cases 2000 --batch 100 \
    --report /tmp/campaign.json --save-crashes /tmp/crashes
```

The runner seeds a corpus from the target's format-aware seeds, mutates with the
shared engine, drives inputs in **batches** (one process for many inputs — ~80×
faster than one-process-per-input), and summarizes real crashes. It is a
real-signal *campaign*, deliberately **not** an experiment-loop environment (see
below).

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

The batch driver amortizes process spawn + `dlopen` over many inputs. Measured on
`mac:imageio` (Xcode 26.6): **~16 exec/s** one-process-per-input vs **~1300
exec/s** at `--batch 100` — roughly an 80× improvement. When a crash occurs
mid-batch the target re-runs that batch input-by-input so each crash is precisely
attributed.

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

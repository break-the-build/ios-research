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

- macOS with a **full Xcode** toolchain (the fuzzer runtime,
  `libclang_rt.fuzzer_osx.a`, is **not** in the Command Line Tools clang).
- `xcode-select -s /Applications/Xcode.app/Contents/Developer` if needed.

The `mac:<framework>` factories are always registered (cheap), but a target is
only `available` once its harness binary is built. CI never builds or runs them.

## Build the harness

```bash
# one framework, or "all"
tools/harness/build.sh imageio
tools/harness/build.sh all
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

## Run it through the pipeline

```bash
ios-research target list                         # mac:* show available=true once built
ios-research fuzz start --target mac:imageio --corpus <dir>
ios-research crash list
ios-research crash reproduce <crash-id>          # re-trigger the real crash
ios-research crash minimize <crash-id>           # ddmin, signature preserved
ios-research crash analyze <crash-id>            # exploitability on a real address
```

## How the target maps outcomes

`MacFuzzTarget._run(data)` writes the input to a temp file, runs
`<harness> <file>` (libFuzzer runs a single input to completion when given a file
argument), and maps the result:

| harness result                                   | `Outcome`  |
|--------------------------------------------------|------------|
| exit `0`                                         | `ACCEPTED` |
| non-zero **with** a recognizable ASan/UBSan report | `CRASH` (+ normalized `Diagnostics`) |
| non-zero **without** a report                    | `ABNORMAL` |
| exceeds the time budget                          | `TIMEOUT`  |
| harness not built / not found                    | `ABNORMAL` (with a build hint) |

`ASAN_OPTIONS=abort_on_error=0:exitcode=99:detect_leaks=0` keeps a full report on
stderr for parsing. The parser (`targets/asan.py`) is defensive: symbolication
varies by OS build, so every field is optional and an unrecognized report still
yields a usable `Diagnostics` with a stable `asan_…` signature keyed on the
classification and top frames (so dedup groups matching crashes despite jittering
addresses).

## Determinism

Follow `RESEARCH-DEVICE.md`: experiments already record the OS build and a config
hash; always `crash reproduce` to confirm a crash re-triggers before triage and
reporting. Native crashes are less perfectly deterministic than the mock path —
the signature is intentionally address-independent so reproductions still group.

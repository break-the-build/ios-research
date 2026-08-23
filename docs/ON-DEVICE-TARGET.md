# Black-Box On-Device Target (confirm on real hardware/OS)

The `mac:<framework>` targets ([MAC-FUZZING.md](MAC-FUZZING.md)) **find and
analyze** bugs with full sanitizer instrumentation on your own machine. The
`ios-device:<surface>` targets do the complementary half: they **confirm that a
crash reproduces on a real, authorized iPhone**, then normalize the platform
crash reporter's `.ips` file into the same `Diagnostics` the rest of the
pipeline consumes.

> **Authorized devices only.** Attach only a device you own or are explicitly
> authorized to test. This target never bypasses permissions, never installs
> persistence, and never performs covert access — it stages one input to a
> surface and reads the crash reporter's own output. See [SECURITY.md](../SECURITY.md).

## Confirmation, not analysis

On a **stock retail device** the only defect signal available is the platform
crash reporter. You cannot:

- run a sanitizer (no ASan/UBSan),
- attach a debugger to system processes,
- observe read/write discrimination or out-of-bounds metadata.

So this path yields **confirmation, not analysis**. A `.ips` crash log gives you
an exception type, a faulting address (often), a backtrace, the loaded modules,
and the OS build — enough to attach a *"reproduces on device (OS build X)"*
evidence line to a finding, but **not** enough to classify OOB-read vs. OOB-write
vs. use-after-free. The parser is deliberately honest about this: a non-null
`EXC_BAD_ACCESS` stays `UNKNOWN` rather than guessing, and only a null-page
fault becomes `NULL_DEREFERENCE`.

| Path | Signal | Classification |
|------|--------|----------------|
| `mac:<framework>` (instrumented) | real registers, access type, OOB metadata | precise (`OUT_OF_BOUNDS_WRITE`, `USE_AFTER_FREE`, …) |
| `ios-device:<surface>` (black-box) | exception, faulting address, backtrace, OS build | coarse (`NULL_DEREFERENCE` / `ASSERTION` / `INTEGER_ERROR` / `UNKNOWN`) |

The productive loop is: **discover + analyze on Mac → confirm on device.**

## Requirements (opt-in; CI stays mock-only)

- A USB-attached, authorized iPhone.
- [`libimobiledevice`](https://libimobiledevice.org/): `brew install libimobiledevice`
  (provides `idevice_id`, `ideviceinfo`, `idevicecrashreport`).

The `ios-device:<surface>` factories are always registered (cheap), but a target
is only `available` once a device is connected **and** the tools are installed.
When either is missing the target degrades gracefully — the CLI stops with a
clear blocker and **writes no crash records** (no fabricated results).

```bash
ios-research target show ios-device:imageio    # available: false, with the blocker
```

## Surfaces

| Surface | Formats | Confirms |
|---------|---------|----------|
| `ios-device:file` | any (`bin`) | any new crash produced on the device |
| `ios-device:imageio` | png, jpeg, gif, tiff, heic, webp | an ImageIO decode crash (pins `MediaPlaybackd` by default) |
| `ios-device:audiotoolbox` | wav, mp3, aac, caf, m4a | an AudioToolbox decode crash |
| `ios-device:coregraphics` | pdf, raw | a CoreGraphics decode crash |

The surfaces mirror the `mac:<framework>` families so a Mac-discovered crash can
be confirmed on the same logical surface on-device.

## How it works

`IosDeviceTarget._run(input)`:

1. **Preconditions** — resolve the device UDID; abort with a clear blocker if no
   device / tools are present.
2. **Baseline** — snapshot the crash reports already on the device (so an old
   report is never mis-attributed to your input).
3. **Deliver** — stage the input to the chosen surface (see *Delivery* below).
4. **Poll** — harvest new crash reports over USB (`idevicecrashreport`) until a
   timeout, matching by **timestamp + process name**. An unpinned generic
   surface with multiple candidates stops as inconclusive rather than guessing.
5. **Normalize** — parse the matched `.ips` (modern JSON *or* legacy text) into
   `Diagnostics`, stamped with the **device id + OS build**.

A non-crashing input produces **no** new matching report and is correctly
classified `ACCEPTED` — it is never recorded as a crash.

## Matching a Mac-discovered crash

```bash
# 1. discover + analyze on macOS (real ASan signal)
tools/harness/build.sh imageio
python tools/mac_campaign/run.py --target mac:imageio --cases 2000 \
    --save-crashes /tmp/crashes

# 2. confirm one candidate reproduces on the device
ios-research fuzz start --target ios-device:imageio --corpus <corpus-with-candidate>
ios-research crash list                 # a CRASH stamped with the device + OS build
ios-research crash reproduce <crash-id> # re-stage + re-harvest to confirm
```

Because real hardware is not perfectly deterministic, always `crash reproduce`
to confirm a crash re-triggers on the device before writing a report. The
experiment already records the device, OS build, and config hash.

## Delivery

Input delivery to an on-device surface is environment-specific — an installed
research app, a share-sheet automation, a local file open — and is intentionally
**not** wired into the framework core. The default `LibimobiledeviceBackend`
harvests whatever the device produces; to drive a concrete, authorized delivery
path, subclass `DeviceBackend` and pass it to `IosDeviceTarget(..., backend=…)`.
The matching + normalization logic is identical regardless of how the input is
staged, which is why it is fully unit-tested against a fake backend.

## Limitations

- **Low analytical signal** by construction (no sanitizer/registers describing
  the access).
- **Process pin required on a busy device** — `ios-device:imageio` uses its
  known `MediaPlaybackd` delivery process by default. Generic `file` and
  delivery-dependent surfaces cannot safely infer a process: pin the exact
  expected name with `IOS_RESEARCH_DEVICE_PROCESS` (or
  `IosDeviceTarget(process=…)`). Without a pin, one new report can be
  confirmed, but multiple reports are an explicit inconclusive blocker rather
  than a guessed crash.
- **One device** — the first connected UDID is used; override with
  `IOS_RESEARCH_DEVICE_UDID`.

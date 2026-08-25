# Connecting an Authorized Research Device

By default every target in `ios-research` is a **mock** target that runs in CI
without any hardware. This document describes how an *authorized* research
device could later be attached behind the same target interface.

> A concrete black-box on-device target now ships: `ios-device:<surface>` stages
> an input to a USB-attached, authorized iPhone and harvests the resulting
> `.ips` crash log (**confirmation, not analysis**). See
> **[ON-DEVICE-TARGET.md](ON-DEVICE-TARGET.md)**. The steps below describe the
> general pattern any device target follows.

> **Authorized research only.** Attach only devices you own or are explicitly
> authorized to test. The framework never bypasses permissions, activates the
> camera/microphone, or performs any covert access — see `SECURITY.md`.

## The target interface

A real device target implements the same lifecycle as the mock targets
(`src/ios_research/targets/base.py`):

```python
class Target:
    target_id: str
    kind: str
    formats: tuple[str, ...]
    mock = False            # a real target sets this to False

    def prepare(self): ...          # connect / stage the input
    def _run(self, data: bytes) -> ExecResult: ...   # run one input
    def cleanup(self): ...          # tear down
```

`execute()` drives `prepare -> _run -> cleanup` and must return a normalized
`ExecResult` with an `Outcome` and, for crashes, deterministic-as-possible
`Diagnostics`.

## Steps to add a device target

1. **Implement a target class** (e.g. `AudioDeviceTarget`) whose `_run` delivers
   the input to the audio-processing entry point on the device and collects the
   result.
2. **Collect diagnostics** from the platform's crash reporter (e.g. an
   `.ips`/spindump/`os_log` capture) and normalize them into `Diagnostics`
   (exception type, faulting address, registers, stack trace, modules).
3. **Register the target** in `targets/__init__.py`:

   ```python
   register("audio-device:wav", lambda: AudioDeviceTarget("wav"))
   ```

4. **Run within an experiment** so results are stamped with the device, OS
   version, and configuration hash:

   ```bash
   ios-research experiment create --device <device-id> --target audio-device:wav
   ios-research fuzz start --target audio-device:wav
   ```

   For the shipped on-device flow, the target id is one of the
   `ios-device:<surface>` targets and the device is resolved per
   [ON-DEVICE-TARGET.md](ON-DEVICE-TARGET.md) (USB attachment +
   `libimobiledevice`); no separate `--device` flag exists on `fuzz start`.

## Determinism note

Real hardware is not perfectly deterministic. Record the device, OS build, and
config hash on every experiment (already done by the experiment model) and use
`crash reproduce` to confirm a crash reproduces before triage and reporting.

## No device? Fuzz macOS system frameworks instead

You do not need a device to get **real** crashes. Many iOS parsing libraries ship
the same binaries on macOS, so a native libFuzzer/ASan harness can `dlopen` a
framework and drive real decode paths on your own machine — producing genuine
faulting addresses, registers, and backtraces through the same pipeline. This is
the most productive real-signal path; see **[MAC-FUZZING.md](MAC-FUZZING.md)**
and the `mac:<framework>` targets.

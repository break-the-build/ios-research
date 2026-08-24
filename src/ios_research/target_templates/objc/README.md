# `{name}` — custom Objective-C target (authorized local harness)

Byte-input Objective-C harness scaffolded by `ios-research target init`.
Deliberately triggerable ASan findings keyed on byte markers (`OOB` → heap OOB
read, `WRT` → heap OOB write, `UAF` → use-after-free); everything else parses
cleanly.

## Platform fallback (Swift/Obj-C)

Apple clang ships no libFuzzer runtime, so this template uses an argv-based
one-input-per-process driver instead of a libFuzzer entry point
(supported-platform fallback documented in docs/TARGET-SDK.md). Build and
validate work wherever the declared toolchain supports the sanitizer profile.

## Build & validate

```bash
ios-research target build  target-manifest.json   # requires cc on PATH
ios-research target validate target-manifest.json
```

The manifest's declared build command runs as argv (never a shell). Set `CC`
to override the default `cc` launcher.

## Authorization

Building and running this target executes user-declared local code on your
own machine. Set `"authorization": {"ack": true}` in `target-manifest.json`
(or pass `--acknowledge-authorized-use` to `target init`) after reviewing
SECURITY.md. Authorized research only.

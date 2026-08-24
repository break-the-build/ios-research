# `{name}` — custom Swift target (authorized local harness)

Byte-input Swift harness scaffolded by `ios-research target init`. Same
OOB/WRT/UAF marker scheme as the C template (heap OOB read / heap OOB write /
use-after-free, all ASan-detectable).

## Platform fallback (Swift/Obj-C)

Apple's toolchain ships no libFuzzer runtime, so Swift/Obj-C templates use an
argv-based one-input-per-process driver instead of `LLVMFuzzerTestOneInput`
(supported-platform fallback documented in docs/TARGET-SDK.md). Build and
validate work wherever the declared toolchain supports the sanitizer profile.

## Build & validate

```bash
ios-research target build  target-manifest.json   # requires swiftc on PATH
ios-research target validate target-manifest.json
```

The manifest's declared build command runs as argv (never a shell). On hosts
without `swiftc`, `target build` fails with a stable STATE error telling you
which tool was missing.

## Authorization

Building and running this target executes user-declared local code on your
own machine. Set `"authorization": {"ack": true}` in `target-manifest.json`
(or pass `--acknowledge-authorized-use` to `target init`) after reviewing
SECURITY.md. Authorized research only.

# `{name}` — custom C++ target (authorized local harness)

Byte-input C++ harness scaffolded by `ios-research target init`, mirroring the
C template's deliberately triggerable ASan findings keyed on byte markers:

| marker in input | finding                    |
|-----------------|----------------------------|
| `OOB`           | heap-buffer-overflow READ  |
| `WRT`           | heap-buffer-overflow WRITE |
| `UAF`           | heap-use-after-free READ   |

## Build & validate

```bash
ios-research target build  target-manifest.json
ios-research target validate target-manifest.json
```

The build prepends the manifest's sanitizer profile flags to `build_cmd`
(argv only — never a shell). Set `CXX`-style overrides by editing
`build_cmd[0]` directly.

## libFuzzer mode

The harness exports `extern "C" LLVMFuzzerTestOneInput`; build with
`-DHARNESS_SDK_NO_MAIN -fsanitize=fuzzer` against a toolchain that ships a
libFuzzer runtime (see docs/TARGET-SDK.md).

## Authorization

Building and running this target executes user-declared local code on your
own machine. Set `"authorization": {"ack": true}` in `target-manifest.json`
(or pass `--acknowledge-authorized-use` to `target init`) after reviewing
SECURITY.md. Authorized research only.

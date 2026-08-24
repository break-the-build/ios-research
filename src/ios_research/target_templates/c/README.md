# `{name}` — custom C target (authorized local harness)

Byte-input C harness scaffolded by `ios-research target init`. It contains
deliberately triggerable, ASan-detectable memory-safety bugs keyed on byte
markers so `target validate` can prove the crash pipeline end to end:

| marker in input | finding                    |
|-----------------|----------------------------|
| `OOB`           | heap-buffer-overflow READ  |
| `WRT`           | heap-buffer-overflow WRITE |
| `UAF`           | heap-use-after-free READ   |

Anything without a marker parses cleanly.

## Build & validate

```bash
ios-research target build  target-manifest.json
ios-research target validate target-manifest.json
```

The build prepends the manifest's sanitizer profile flags to `build_cmd`
(argv only — never a shell). Set `CC` to override the default `cc` launcher.

## libFuzzer mode

The harness exposes `LLVMFuzzerTestOneInput`. To build against a real
libFuzzer runtime (not shipped by Apple clang), define `-DHARNESS_SDK_NO_MAIN`
and link with `-fsanitize=fuzzer` — see docs/TARGET-SDK.md.

## Authorization

Building and running this target executes user-declared local code on your
own machine. Set `"authorization": {"ack": true}` in `target-manifest.json`
(or pass `--acknowledge-authorized-use` to `target init`) after reviewing
SECURITY.md. Authorized research only.

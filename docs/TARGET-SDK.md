# Custom Target SDK (authorized user-declared harnesses)

Wrap your *own* parsing harness as a first-class ios-research target without
touching framework code. The SDK only ever builds and runs **local,
user-declared** targets on your own machine — no device bypass, persistence, or
exploit features (`SECURITY.md`). Building/running executes your code and
therefore requires an explicit authorization acknowledgement
(`authorization.ack: true` in the manifest).

## Workflow

```bash
# 1. write a template project (c | cpp | swift | objc)
ios-research target init --language c --dest ~/targets/sample --name sample \
    --acknowledge-authorized-use

# 2. build via the manifest argv (no shell; sanitizer flags come from the profile)
ios-research target build ~/targets/sample/target-manifest.json

# 3. prove seed health, crash parsing, reproducibility
ios-research target validate ~/targets/sample/target-manifest.json

# 4. register as custom:<name> (runtime registry + workspace provenance record)
ios-research target register ~/targets/sample/target-manifest.json

# 5. standard pipeline — fuzz, reproduce, minimize, report
ios-research fuzz start --target custom:sample --max-cases 500
ios-research crash list && ios-research crash minimize <id>
```

`register` persists a record under `targets/` in the workspace (manifest hash,
environment, build provenance), so later CLI invocations re-resolve
`custom:<name>` automatically — no code changes, no re-registration.

## Manifest (schema_version 1)

`target-manifest.json` pins: `name`, `language`, `source`, `build_cmd`
(argv list with a `{out}` placeholder — never a shell string), `output_path`,
`seeds`, optional `dictionary`, `sanitizer_profile`
(`ios_research.sanitizers` id), `timeout_s`, and
`authorization: {"ack": bool}`. Invalid manifests fail with a stable
`VALIDATION` error listing every problem; an unavailable toolchain fails with
a stable `STATE` error.

## Templates and markers

Templates ship as plain-text package assets under
`src/ios_research/target_templates/<language>/` — one byte-input harness
source, a default `target-manifest.json`, and a README snippet that `target
init` materializes into your project directory (`{name}` placeholders are
substituted at init time). Templates are byte-input harnesses with deliberately
triggerable ASan bugs keyed on byte markers (`OOB` → OOB read, `WRT` → OOB
write, `UAF` → use-after-free), modeled on the `mac:selftest` harness, so
`target validate` can prove real crash parsing end to end. C/C++ also expose a
libFuzzer-compatible `LLVMFuzzerTestOneInput`; Swift/Obj-C use an argv-based
driver because Apple clang ships no libFuzzer runtime (supported-platform
fallback: validate/build them wherever the declared toolchain supports the
profile). Set `CC` to override the default `cc` launcher.

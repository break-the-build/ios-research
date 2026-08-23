# Protocol & Format Suites (#47)

A *suite* is a versioned, self-contained directory bundling everything a
campaign needs for one safe protocol or file format: seed corpus, token
dictionary, grammar/mutator plugins, state machine, oracle definitions,
license and provenance. Suites never modify core code.

## Manifest

`suite.json` (schema_version 1): `name`, `version` (semver `X.Y.Z`),
`description`, `license`, `compatibility.framework`
(`ios-research`) + `compatibility.min_framework_version`, and `contents`
(`seeds_dir` required; `dictionary`, `plugins`, `state_machine`, `oracles`
optional). All paths are relative and must resolve inside the suite dir —
absolute paths and `..` escapes are rejected before any file is read.
Unknown fields are rejected.

## CLI

```text
ios-research suite example --out D     # built-in mock-record suite (MIT)
ios-research suite validate D          # structured problems; invalid never raises
ios-research suite install D           # copies to <workspace>/suites/<name>-<version>/
ios-research suite list
ios-research suite show NAME [--version V]
ios-research suite benchmark NAME --target T --cases N --seed S   # N <= 200
ios-research suite remove NAME --version V                        # needs --yes
```

## Guarantees

- Invalid/incompatible suites fail safely: validation returns
  `{valid, problems}` instead of raising; installs of broken suites are
  refused with a stable `VALIDATION`/`STATE` error.
- Installs record provenance plus SHA-256 of every copied file in
  `.iosr-install.json`; duplicate name-version installs are refused.
- Benchmarks run through the deterministic fuzz engine using only suite
  seeds/dictionary, so identical `(suite, target, cases, seed)` inputs give
  identical `{executed, unique_features, outcomes}` stats anywhere.

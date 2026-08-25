# Releases and compatibility

## Compatibility

The JSON output envelope (`ok`, `command`, `data`, `messages`, `error`, and
`exit_code`) is a public contract. Backward-incompatible changes to that
envelope, command names, or documented schema require a major release and
migration notes. Deprecations must be documented for at least one minor
release where practical.

## Release checklist

- Update `CHANGELOG.md` and version metadata.
- Run the full CI matrix and regenerate `docs/cli-schema.json`.
- Publish upgrade notes and supported Python/macOS versions.
- Attach source archives from the tagged commit and publish their SHA-256
  hashes. Prefer GitHub's artifact attestations when releases are automated.

Users should install from a tagged release or verify the commit and checksums
before relying on results in a security workflow.


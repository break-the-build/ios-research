# Reproducible campaign standard

Results from mock targets are framework validation, not evidence of a product
vulnerability. Claims about an authorized target require the target owner's
authorization and retained artifacts.

## Required record

For every reportable campaign, retain the commit SHA, framework version,
operating system and toolchain, target and authorization record, device/OS
matrix when applicable, command/configuration, random seed, corpus hashes and
provenance, raw logs, crash inputs, reproduction output, and report artifacts.

Store this information in a versioned campaign manifest alongside the results.
Never include credentials, private target data, or unpublished vulnerability
details in a public manifest.

## Minimal synthetic example

```bash
ios-research init
ios-research research create --target mock:parser --max-cases 100
ios-research research run --yes
ios-research research summarize --json > campaign-summary.json
git rev-parse HEAD > campaign-commit.txt
```

Record the exact command, generated summary, commit, and Python version. A
third party can then rerun the same mock campaign without a device.


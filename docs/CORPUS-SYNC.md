# Corpus Synchronization (#32)

Workers exchange corpora through append-only, content-addressed bundles moved
by your own transport — no network is involved.

## Bundle format

```
<bundle>/bundle.json          # hash-verified manifest
<bundle>/inputs/<sha256>.bin  # one content-addressed input per entry
```

`bundle.json`: `{schema_version: 1, kind: "iosr-corpus-bundle", worker_id,
target, created_at_cursor, entries: [{sha256, size, origin, parent, mutation,
seed, iteration, coverage_features}] sorted by sha256, manifest_sha256}` where
`manifest_sha256` = SHA-256 over the canonical JSON of all other fields.
Export is deterministic: the same corpus yields a byte-identical `bundle.json`.

## Import safety

- The bundle directory **must** be under an explicit `--allow-root` (fail
  closed otherwise); no implicit discovery, no network access.
- Manifest hash + every input's sha256/size verify before anything is written;
  one malformed entry aborts the whole import atomically.
- Content-addressed writes make imports idempotent: duplicates are skipped, so
  re-running an interrupted import converges to the same final state.
- `--minimize` runs a greedy coverage set-cover over stored features only
  (no target execution) so imports cannot bloat the active corpus.

```bash
ios-research sync export cor_x --out /srv/exchange/w1 --worker w1 --cursor 12000
ios-research sync import cor_y /srv/exchange/w1 --allow-root /srv/exchange --minimize
ios-research sync status --worker D1 --worker D2   # read-only rollup + lag
```

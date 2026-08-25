# Beta-Window Parser Diffing (#228 §3)

Status: **operational workflow** — `staticscan diff` is live (CLI + tests);
this document is the runbook for using it during an OS beta window
(+50% bounty bonus window).

## Why

New format tokens in a shipped binary are evidence of newly added or newly
reachable parsers. During a beta window that code is (a) least audited and
(b) explicitly eligible for the +50% bonus — so the highest-EV directed
campaigns of the year are aimed by a two-minute static diff, not guesswork.

## The loop

Run on the **beta** host after install (and again on each beta seed; keep
every record):

```bash
BUILD=$(sw_vers -buildVersion)

# 1. Resolve where the parser code actually lives (cryptex-era macOS/iOS:
#    loose framework paths are broken symlinks; code is in the dyld cache).
ios-research staticscan locate CoreGraphics --json

# 2. Snapshot the parser surface — whole-cache record (~1-2 min) and, for
#    per-framework precision, extracted dylibs (#237 path).
CACHE=$(ios-research staticscan locate CoreGraphics --json \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["cache_path"])')
ios-research staticscan fingerprint "$CACHE" --json \
  > "artifacts/beta/fp-cache-${BUILD}.json"
for fw in ImageIO CoreGraphics CoreText AudioToolbox VideoToolbox; do
  ios-research staticscan extract "$fw" --out artifacts/beta/dsc-${BUILD} --json
  DYLIB=$(ls artifacts/beta/dsc-${BUILD}/*${fw}* | head -1)
  ios-research staticscan fingerprint "$DYLIB" --json \
    > "artifacts/beta/fp-${fw}-${BUILD}.json"
done

# 3. Diff against the previous release's saved records.
ios-research staticscan diff artifacts/beta/fp-cache-<old>.json \
                              artifacts/beta/fp-cache-${BUILD}.json --json
```

Notes:

- `diff` accepts **binary paths or saved JSON documents** (anything with a
  `matches` mapping). Saving per-build records once means repeated diffs of a
  huge dyld shared cache never re-pay the strings pass (a full-cache
  fingerprint costs ~1–2 min; a saved record diffs instantly).
- Whole-cache diffs see *everything* that shipped; extracted-dylib diffs are
  the precise per-family follow-up when the cache-level diff flags a family.
- Output is deterministic: per-family `added`/`removed` token sets,
  `added_token_count`, and a flat `directed_targets` list (families with
  additions, sorted) for campaign aiming.

## Aiming campaigns at the result

1. **New-token families → dictionary**: regenerate the evidence dictionary
   for that family (`staticscan dict <new-binary> --families <family>`) and
   pass it to the campaign (`--extra-dict` / libFuzzer `-dict=`).
2. **Deep entry points first**: aim the deep-decode harnesses (#228 §2:
   imageio full-frame render, coregraphics page render + operator sweep,
   audiotoolbox packet+convert, videotoolbox session decode) at any family
   with additions — front-door opens under-exploit new parser code.
3. **Call-graph focus**: if the changed family warrants it, extract the dylib
   (`staticscan extract`), run Ghidra headless, and use
   `staticscan callgraph --focus` to pick directed-fuzzing focus functions
   that reference the new constants (#237 path).
4. **Record provenance**: file the diff record id/build strings in the
   experiment notes so a later finding can cite *which beta build* introduced
   the parser (patch-regression validation via `cve validate` also benefits).

## Cadence

| Event | Action |
|---|---|
| Beta 1 install | fingerprint all fuzzed frameworks; baseline = last release records |
| Each subsequent seed | re-diff; re-aim dictionaries/campaigns at cumulative additions |
| GM / public release | final diff; keep records for patch-regression baselines |

Negative result (no new tokens) is recorded honestly — it means the beta did
not touch the surfaces we can reach, and the next window starts from the new
baseline.

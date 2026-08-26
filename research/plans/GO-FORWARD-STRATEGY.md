# Go-Forward Strategy — from liveness findings to bounty-grade evidence

Status: strategy of record after the 0825 session. Review date: 2026-08-26.
Owner: primary researcher (LLM-assisted execution).

## 1. Honest position assessment

Four findings shipped or drafted, all **liveness/policy** class, zero memory
corruption:

| Finding | Class | Device result |
|---|---|---|
| FINDING-04 AudioToolbox MPEG/ID3 hang | liveness | reproduces on iPhone |
| FINDING-05 CoreGraphics text-advances hang | liveness | macOS-only |
| FINDING-06 CoreText morx-shaping hang | liveness | macOS-only, 3 families |
| FINDING-07 IOTimeSync unprivileged gPTP port create | policy/validation | macOS-only (beta dynamic pending) |

Apple Security Bounty rewards **demonstrable exploitability**. Hangs are
explicitly below the threshold; policy/validation findings typically rate
acknowledgment at best. The 0825 pipeline is exceptionally good at *finding
liveness bugs* — which is exactly the problem. **The pivot: stop optimizing
for "where can we detect misbehavior" and optimize for "where can corruption
be reached and demonstrated."**

Assets that change the odds:

- The IOKit recon pipeline (symtab diff → MIG tables → externalMethod
  dispatch parse → validation audit) produced FINDING-07 in one day of work.
- Beta artifacts for macOS 27 b7 and iOS 27 b7 are staged; the **+50% beta
  bonus** applies to anything found in that window.
- The on-device confirmation flow (AudioProbe + bridge + crash harvest) is
  mature and reusable across surfaces.
- Five deep-decode mac harnesses exist and are caffeinate-hardened for
  unattended windows.

## 2. Phase 0 — FINDING-07 closure + first corruption dig (this week)

1. **Submit FINDING-07** to product-security@apple.com for a tracking
   identifier. Reward is unlikely and the draft says so honestly; the value
   is a clean, well-documented kernel report on file (track record and
   relationship), at near-zero marginal cost. Attach probe sources, per-call
   logs, and the selector-map documentation.
2. **Beta confirmation**: static review of b7 shows the identical ungated
   selector set; capture dynamic confirmation when the beta environment is
   available and update the draft before sending.
3. **In parallel — mine the same user client for corruption**: selectors
   18–31 accept scalar/structure input from any caller. Enumerate argument
   shapes with `extmethod.py`, identify every structure/OOL-descriptor input,
   and audit those paths in the b7 dylib for missing bounds/ownership checks.
   The embedded-NUL interface-name path proves name handling has edges; the
   port-id refcount path is the next obvious audit target.

Exit criteria: FINDING-07 sent with tracking id recorded; a written
selector-by-selector validation map for 18–31; any corruption candidate
escalated to its own FINDING.

## 3. Phase 1 — kernel user-client corruption hunt (weeks 1–2)

Primary bounty line. Ordered by (reachability × novelty × audit gap):

1. **`is_iokit_subsystem` num 2891** — unnamed, 7-arg, max_reply 208, new in
   b7, reachable from any sandboxed process holding a connect handle. Locate
   the impl pointer in the beta kernelcache, decompile (Ghidra pipeline is
   proven — see `tools/staticscan/README.md`), audit the 7-argument
   validation, build a targeted probe. An unknown MIG routine with no public
   history is the single highest-novelty target on the board.
2. **IOTimeSync selectors with structure/OOL inputs** (continuation of
   Phase 0 step 3).
3. **`AFKSharedMemoryUserClient`** (+28 syms; shared-memory mapping user
   clients are the classic memory-corruption class; new HID-transport kext).
4. **`Image4UserClient`** (+20; manifest parsing adjacent to trust decisions).

Method per target, in order: static validation audit first (free, safe),
then bounded host-side `IOConnect` probing on our own machine (panic risk
accepted and bounded — own hardware, authorized), fuzzing structure/OOL
arguments only after the static map says where the checks should be.

Exit criteria: per-target one-page audit notes in `research/findings/`;
probes checked into `tools/probe/`; any crash escalated through the standard
pipeline (reproduce → minimize → analyze → device-confirm where applicable).

## 4. Phase 2 — beta-window campaigns (+50%) after the iPhone flash

Requires user go-ahead (iOS 27 b7 flash wipes the phone; OTA is staged in
`/Users/danny/dev/betas/`):

1. Flash iPhone 13 Pro → iOS 27 b7; re-pair; re-trust developer cert.
2. Re-run on-device tiers: media confirms (FINDING-04/05/06 beta retests —
   drafts already promise these), BT window (`ble_window.py`), and the
   Phase-1 probes that have on-device reach.
3. Re-baseline: `staticscan fingerprint` the b7 dyld cache, `diff` against
   26.5.2 records (workflow: `research/plans/BETA-WINDOW-DIFF-WORKFLOW.md`),
   aim dictionaries and campaigns at `directed_targets`.
4. macOS 27 b7 on the Studio: **deferred decision** — it is the primary
   research machine; image first or use a secondary Mac before upgrading.

Exit criteria: beta retest section appended to every existing finding;
beta-baseline fingerprint records committed to `artifacts/beta/`.

## 5. Phase 3 — continuous background (not the bounty path)

Overnight caffeinated campaigns on the five mac harnesses and the BT window.
Value: corpus depth, coverage records, regression detection between OS
builds. Explicitly **not** the primary bounty line — liveness findings from
these are recorded honestly and not submitted unless a family shows
corruption.

## 6. Process debt (scheduled, small)

- **CI enforcement** (#153): 1,700+ tests never run automatically — the
  single cheapest reliability win; wire a GitHub Actions mock-only gate.
- **Worktree-first discipline**: three concurrent-agent collisions this
  session (branch switches wiping uncommitted work). All LLM work happens in
  `.worktrees/<name>`; the main checkout is the other agent's.
- `ble_window.py` reads-counter regex nit (char/desc reads counted 0 in
  window mode; manual runs confirm they flow).
- Kernel recon deliverables consolidation: `/tmp/opencode/` artifacts are
  the only copy of several recon outputs — copy into
  `betas/campaign-0825/kernel-iokit/` and commit.

## 7. Decision log

| Decision | Rationale |
|---|---|
| Submit FINDING-07 despite low reward odds | track record + relationship; cost ≈ 0 |
| Pivot primary effort to kernel user clients | only surface class we can reach that pays |
| iPhone beta flash requires explicit user go-ahead | destructive (wipe); staged OTA ready |
| macOS 27 b7 on Studio deferred | primary research machine; image-or-secondary first |
| RF-injection tier stays parked | hardware prerequisite; Apple-CID system-parse surface documented for when it exists |
| Media harness campaigns demoted to background | they find liveness; liveness doesn't pay |

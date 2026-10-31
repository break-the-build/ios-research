# Go-Forward Strategy — reach and oracles, not more of the same

Status: strategy of record, rewritten 2026-10-30 (supersedes the 2026-08-26
version, which is in git history). Next review: 2026-11-06, after iOS 27.3
beta 1 lands. Owner: primary researcher (LLM-assisted execution).

**Disclosure rule for this file:** this repository is public. Unreported
findings, open leads and probe details live only in `research/findings/`
(gitignored); this file states outcomes and directions, never specifics an
outsider could act on before Apple has a report.

## 1. Position (2026-10-30)

| Outcome | Count |
|---|---|
| Memory-corruption findings | 0 |
| Liveness (hang) reports to Apple | 3, all closed at $0: "defense-in-depth", "functional performance issue", acknowledgment credit without a CVE |
| Policy-class kernel report | 1, drafted; not sent as of 2026-10-30 |
| Kernel user-client static audits (beta 7 additions) | all hardened, no findings (#280) |
| Guard Malloc executions on the current media corpora | ~95M, 0 crashes |

Apple pays for demonstrated memory corruption and boundary crossings, not
hangs. The August strategy predicted the hang outcomes correctly. Liveness
reports are not submitted any more unless a family shows corruption.

## 2. What changed: the media lane was judged with a blind oracle

The August decision demoted media-parser fuzzing because "it finds liveness;
liveness doesn't pay". From 2026-08-23 (`f633896`) to 2026-10-29 (`1b6416d`)
the mac harnesses ran ASan over **harness code only**: a heap overflow inside
ImageIO, CoreText, CoreGraphics or AudioToolbox returned normally and was never
seen. Those campaigns could only ever find hangs, so the demotion rested on a
detector that could not see the paying bug class.

Since 1b6416d the harnesses run under Guard Malloc. The first ~95M executions
on the existing corpora found nothing, so those corpora are **saturated**:
another seed or another million cases on them has close to zero expected value.
Two variables still change the odds:

1. **Reach:** code we have never executed. The corpora contain no DNG/camera
   RAW, no WebP/EXR/PSD/JPEG 2000/texture formats, two PNGs and two JPEG XL
   files, no HE-AAC/USAC/Opus/FLAC/APAC/AC-3, and only a handful of system
   PDFs. Until 2026-10-30 the CoreText harness never drew a glyph (#302).
2. **Oracles:** bug classes the default oracle misses: 1–15-byte overflows
   (strict size, where usable: section 6), underflows (protect-before), and
   uninitialized memory copied into output (fill-space differential).

Apple's in-the-wild fixes say where to aim, and bugs cluster around them:

| Lane | Anchor (public) |
|---|---|
| DNG / camera RAW (ImageIO) | CVE-2025-43300: TIFF tags vs embedded JPEG header mismatch |
| Audio codecs and containers | CVE-2025-31200: CoreAudio APAC decoder |
| PDF image filters (CoreGraphics) | CVE-2021-30860 (FORCEDENTRY): JBIG2 via PDF |
| ImageIO formats the corpus lacks, PNG/APNG fields | CVE-2023-41064 (BLASTPASS): ImageIO WebP |
| Fonts (CoreText / FontParser) | CVE-2023-41990: TrueType hinting instruction |

## 3. Primary line: media reach lanes (weeks 1–2)

Executed from a handoff kept outside the repo. Per lane: build a gated seed
corpus with structured generators (field-mismatch variants patched in place,
not random bytes), sweep every variant directly under each usable oracle, grow
a framework-coverage corpus with Jackalope, then Guard Malloc campaigns on it.

**Kill criteria, per lane:**
- Gate: under 50% of a format's seeds decode → fix the generator within 30 min
  or drop that format and record why.
- Close the lane when the direct sweep found no candidate, 2 h of Jackalope
  added no new offsets in its last 30 min, and 1M cases per usable oracle
  found no candidate. Record the numbers; reopen only with new reach.
- One-hour rule: a signal that has not produced a file crashing the standalone
  Guard Malloc harness 3/3 within an hour of effort is recorded and dropped.

**What counts:** only a file that crashes the standalone Guard Malloc harness
3 times out of 3. OS crash reports, dead batches and Jackalope crashes are not
findings (23 fake reports from a Jackalope teardown bug cost a whole scan,
fixed in #302). A memory-corruption bug in a shared framework is reportable
from macOS alone (macOS is in scope); confirm iOS reach afterwards for
severity.

## 4. Beta window: iOS 27.3 beta 1 (expected ~2026-11-02)

New code is the least-fuzzed code, and findings in the beta window carry the
+50% bonus. Before it lands:

1. Re-validate the iPhone's research setup (pairing, developer mode, the
   on-device confirmation harness): a macOS crash becomes an iOS report only
   through it.
2. Prepare the diff: shared frameworks plus FontParser, RawCamera and
   AudioCodecs, 27.2 → 27.3b1; map new or changed functions to the lanes.
3. When it lands: point the lane generators at changed formats first; run the
   kernel side of `BETA-TRIAGE-CHECKLIST.md` for new user clients and MIG
   routines.

## 5. Kernel line: reopened only by a beta diff

The beta 7 kernel additions were audited statically and were hardened. The
SMB client rig is parked: its one observation was a liveness-class wedge.
Kernel work resumes when a beta diff shows new user clients, new MIG routines
or changed validation, using the proven pipeline (symbol diff → dispatch-table
parse → static validation audit → bounded probe on own hardware).

## 6. Process rules

- **Detection canary before every campaign** (`tools/mac_campaign/run.py`
  runs it; `canary_all.sh` after OS updates): a positive control (a framework
  read into a guard page must be detected and classified) and a negative one (a
  valid seed must not crash). A failing oracle is not used. On macOS 26.x
  `MALLOC_STRICT_SIZE` crashes the imageio, audiotoolbox and coregraphics
  harnesses on valid input; only coretext can use it.
- **Worktree-first:** every agent works in `.worktrees/<name>`; the main
  checkout belongs to whoever owns it. Kill processes by PID, never by
  pattern; never run `tools/harness/build.sh` under a running campaign.
- **Weekly scoreboard:** per lane, hours spent, new framework offsets reached,
  candidates. A lane with flat offsets and no candidates is closed (section 3).
- **Records:** findings, Apple thread IDs and proofs of concept live in
  `research/findings/` and need an off-machine backup; handoffs are versioned.

## 7. Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-08-26 | Stop submitting liveness findings | Apple rewards corruption; confirmed by three $0 dispositions (2026-10) |
| 2026-08-26 | iPhone beta flash only with explicit go-ahead | destructive (wipe) |
| 2026-10-29 | Guard Malloc is the default harness oracle | ASan on the harness never saw bugs inside the frameworks |
| 2026-10-30 | Media reach lanes are the primary line; corpus replay is background at most | the August demotion was made with a blind oracle; current corpora are saturated |
| 2026-10-30 | Kernel work reopens only on a beta diff | beta 7 additions audited and hardened; SMB rig showed liveness only |
| 2026-10-30 | No campaign without a passing detection canary | a dead oracle went unnoticed for two months |
| 2026-10-30 | No unreported findings or leads in tracked files | the repository is public; disclosure before Apple's advisory endangers eligibility |

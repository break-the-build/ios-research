#!/usr/bin/env python3
"""Uninitialized-memory differential for the ImageIO and CoreText harnesses.

A decoder that copies uninitialized heap into its output never crashes, but it
discloses process memory ("processing an image may result in disclosure of
process memory" is a recurring line in Apple's security notes). Guard Malloc
hands out zeroed fresh pages; MALLOC_FILL_SPACE=1 fills every new allocation
with 0x55 instead. The harness prints a digest of its output pixels
(IOSR_DIGEST=1), so for each file:

    plain run x2, fill run x2:  both pairs agree, and plain != fill  -> HIT
                                a pair disagrees                     -> unstable
                                all four agree                       -> clean

Controls run first, on one of the target's own seeds: the positive control
(IOSR_UNINIT_CANARY=1: output buffers left uninitialized, plus a row the
framework never writes) must be a HIT, and the same seed without it must be
clean. Without Guard Malloc the canary's bytes are random and the controls
fail; nothing is scanned with a dead oracle.

Authorized / own-machine research only (SECURITY.md).

Usage:
    python tools/mac_campaign/uninit.py --target mac:imageio DIR_OR_FILE ... \\
        [--out HITS_DIR] [--report FILE]
    python tools/mac_campaign/uninit.py --target mac:coretext --controls-only

Exit codes: 0 ok, 2 usage, 3 harness not built, 4 controls failed.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys

_REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "src"))

from ios_research.targets import create  # noqa: E402

SUPPORTED = ("imageio", "coretext")
BATCH = 64
PER_FILE_TIMEOUT_S = 15
EXIT_USAGE, EXIT_NOT_BUILT, EXIT_CONTROLS_FAILED = 2, 3, 4
FILL = {"MALLOC_FILL_SPACE": "1"}


def _digests(harness: str, files: list[str], extra_env: dict[str, str]) -> dict[int, str]:
    """index -> output digest for every file that produced output.

    A crashing file (another oracle's business) is skipped: the batch is
    re-run one file at a time so the others still get a digest.
    """
    env = {**os.environ, "IOSR_DIGEST": "1", **extra_env}
    out: dict[int, str] = {}
    for start in range(0, len(files), BATCH):
        chunk = files[start:start + BATCH]
        try:
            proc = subprocess.run([harness, *chunk], capture_output=True, env=env, check=False,
                                  timeout=PER_FILE_TIMEOUT_S * len(chunk))
            ok = proc.returncode == 0
        except subprocess.TimeoutExpired:
            ok = False
        if not ok and len(chunk) > 1:
            for i, path in enumerate(chunk):
                one = _digests(harness, [path], extra_env)
                if 0 in one:
                    out[start + i] = one[0]
            continue
        if not ok:
            continue
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[0] == "DIGEST":
                out[start + int(parts[1])] = parts[2]
    return out


def classify(plain: tuple[str | None, str | None], fill: tuple[str | None, str | None]) -> str:
    if None in plain or None in fill:
        return "no-output"
    if plain[0] != plain[1] or fill[0] != fill[1]:
        return "unstable"
    return "hit" if plain[0] != fill[0] else "clean"


def scan(harness: str, files: list[str], extra_env: dict[str, str] | None = None) -> list[str]:
    """The verdict for each file, in order."""
    base = extra_env or {}
    p1, p2 = _digests(harness, files, base), _digests(harness, files, base)
    f1, f2 = (_digests(harness, files, {**base, **FILL}) for _ in range(2))
    return [classify((p1.get(i), p2.get(i)), (f1.get(i), f2.get(i)))
            for i in range(len(files))]


def controls(harness: str, seeds: list[bytes], workdir: pathlib.Path) -> tuple[bool, str]:
    """Positive and negative controls on the first seed that produces output."""
    workdir.mkdir(parents=True, exist_ok=True)
    for i, data in enumerate(seeds):
        path = workdir / f"control_seed_{i}"
        path.write_bytes(data)
        negative = scan(harness, [str(path)])[0]
        if negative == "no-output":
            continue
        if negative != "clean":
            return False, (f"negative control: a valid seed is {negative} without the canary "
                           f"(the measurement is noisy, or the seed itself leaks: inspect it)")
        positive = scan(harness, [str(path)], {"IOSR_UNINIT_CANARY": "1"})[0]
        if positive != "hit":
            return False, (f"positive control: uninitialized output was {positive}, not a hit "
                           f"(Guard Malloc or MALLOC_FILL_SPACE is not in effect)")
        return True, f"controls passed on seed {i}"
    return False, "no seed produced output to run the controls on"


def _files(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in map(pathlib.Path, paths):
        out.extend(sorted(str(f) for f in p.rglob("*") if f.is_file()) if p.is_dir()
                   else [str(p)])
    return out


def main(argv=None, *, harness: str | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="mac:imageio",
                    help=f"mac:<framework>, one of {', '.join(SUPPORTED)}")
    ap.add_argument("paths", nargs="*", help="files or directories to scan")
    ap.add_argument("--out", default=None, help="copy each hit here")
    ap.add_argument("--report", default=None, help="write the JSON summary here")
    ap.add_argument("--controls-only", action="store_true",
                    help="run only the positive and negative controls")
    args = ap.parse_args(argv)

    key = args.target.split(":", 1)[-1]
    if key not in SUPPORTED:
        print(f"error: {args.target} has no output digest (want mac:imageio or mac:coretext)",
              file=sys.stderr)
        return EXIT_USAGE
    target = create(args.target)
    harness = harness or (str(target.resolve_harness() or "") or None)
    if not harness:
        print(f"error: harness for {args.target} is not built "
              f"(tools/harness/build.sh {key})", file=sys.stderr)
        return EXIT_NOT_BUILT

    import tempfile
    with tempfile.TemporaryDirectory(prefix="iosr-uninit-") as tmp:
        ok, reason = controls(harness, target.seeds(), pathlib.Path(tmp))
    print(f"controls: {'PASS' if ok else 'FAIL'}: {reason}", file=sys.stderr)
    if not ok:
        return EXIT_CONTROLS_FAILED
    if args.controls_only:
        return 0

    files = _files(args.paths)
    verdicts = scan(harness, files)
    hits = [f for f, v in zip(files, verdicts) if v == "hit"]
    counts = {v: verdicts.count(v) for v in ("hit", "unstable", "clean", "no-output")}
    summary = {"target": args.target, "files": len(files), "counts": counts,
               "hits": hits,
               "unstable": [f for f, v in zip(files, verdicts) if v == "unstable"]}
    if args.out and hits:
        dest = pathlib.Path(args.out)
        dest.mkdir(parents=True, exist_ok=True)
        for f in hits:
            shutil.copy2(f, dest / pathlib.Path(f).name)
    text = json.dumps(summary, indent=2)
    if args.report:
        pathlib.Path(args.report).write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

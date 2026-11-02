#!/usr/bin/env python3
"""Decode gate for generated seeds: how many decode, per variant kind.

Runs the standalone harness over a directory in batches and parses its DONE
lines. A file counts as decoded when the harness says ``decoded`` with a
non-zero depth metric (``pixels=`` / ``frames=``), or just ``decoded`` for
targets without one. Files that crash the harness are copied to
``--crashes`` (a crash at the gate is a candidate: triage it 3/3). Files that
run past ``--timeout`` seconds are hangs, counted and copied to ``--hangs``
apart from crashes; on a loaded machine most are just slow. Kinds come from
the generators' variant names (``Arial-hint-glyph12-7.ttf`` -> ``hint-glyph``,
``x-ifd1-jpegNf-4.dng`` -> ``ifd1-jpegNf``), so a generator mode that rarely
decodes stands out.

Authorized / own-machine research only (SECURITY.md).

Usage:
    python tools/gen/gate.py --target mac:coretext DIR [--ok OK_DIR] [--crashes DIR]
        [--hangs DIR] [--timeout 15]
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
from collections import Counter

_REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "src"))

from ios_research.targets import create  # noqa: E402

BATCH = 64
PER_FILE_TIMEOUT_S = 15
HANG_EXIT = 124                 # tools/harness/harness_runtime.h, per-input deadline
# Added to every harness call's wall-clock budget: process start (dyld, the
# Guard Malloc re-exec) can take seconds on a loaded machine, and before the
# first input starts no per-input deadline is armed.
STARTUP_GRACE_S = 30
_KIND_RE = re.compile(r"(tbl-[A-Za-z0-9_]+|hint-[a-z]+|ifd\d+-(?:pair|[A-Za-z]+))")


def kind(path: pathlib.Path) -> str:
    m = _KIND_RE.search(path.stem)
    return m.group(1) if m else "other"


def _status(line: str) -> tuple[int, bool] | None:
    parts = line.split()
    if len(parts) not in (3, 4) or parts[0] != "DONE":
        return None
    ok = parts[2] == "decoded" and (len(parts) == 3 or not parts[3].endswith("=0"))
    return int(parts[1]), ok


def _hung(proc) -> bool:
    """The driver ended on its per-input deadline (exit 124, IOSR-HANG)."""
    return proc is not None and proc.returncode == HANG_EXIT and b"IOSR-HANG" in proc.stderr


def _hang_index(proc) -> int | None:
    """The input index an IOSR-HANG line names, if any."""
    m = re.search(rb"IOSR-HANG input=(\d+)", proc.stderr) if _hung(proc) else None
    return int(m.group(1)) if m else None


def _invoke(harness: str, chunk: list[pathlib.Path], env: dict, timeout_s: float):
    """The finished process, or None when it outran its wall-clock budget."""
    try:
        return subprocess.run([harness, *map(str, chunk)], capture_output=True, check=False,
                              env=env, timeout=timeout_s * len(chunk) + STARTUP_GRACE_S)
    except subprocess.TimeoutExpired:
        return None


def _statuses(proc) -> list[tuple[int, bool]]:
    lines = proc.stdout.decode("utf-8", "replace").splitlines() if proc is not None else []
    return [st for st in map(_status, lines) if st]


def run(harness: str, files: list[pathlib.Path], hung: list[int] | None = None,
        timeout_s: float = PER_FILE_TIMEOUT_S) -> tuple[dict[int, bool], list[int]]:
    """index -> decoded, plus the indexes that crashed (isolated one by one).

    The harness gets a per-input deadline (``timeout_s``). A hang ends its
    batch on that input; the inputs before it keep their results and the batch
    resumes after it. Given a ``hung`` list, inputs that hang -- by the
    harness's deadline or by outrunning the wall-clock budget, which on a
    loaded machine is the same thing -- go there instead of into the crashes.
    """
    decoded: dict[int, bool] = {}
    crashed: list[int] = []
    env = {**os.environ, "IOSR_INPUT_TIMEOUT": str(max(1, int(timeout_s)))}
    start = 0
    while start < len(files):
        chunk = files[start:start + BATCH]
        proc = _invoke(harness, chunk, env, timeout_s)
        statuses = _statuses(proc)
        if proc is not None and proc.returncode == 0:
            for i, ok in statuses:
                decoded[start + i] = ok
            start += len(chunk)
            continue
        stuck = _hang_index(proc)
        if stuck is not None and stuck == len(statuses) and stuck < len(chunk):
            for i, ok in statuses:                    # the inputs before the hang
                decoded[start + i] = ok
            (hung if hung is not None else crashed).append(start + stuck)
            decoded[start + stuck] = False
            start += stuck + 1                        # resume after it
            continue
        if len(chunk) == 1:
            if hung is not None and (proc is None or _hung(proc)):
                hung.append(start)
                decoded[start] = False
            else:
                crashed.append(start)
            start += 1
            continue
        for i in range(len(chunk)):                   # a crash: isolate every input
            sub_hung: list[int] | None = [] if hung is not None else None
            sub_dec, sub_crash = run(harness, [chunk[i]], sub_hung, timeout_s)
            if sub_crash:
                crashed.append(start + i)
            elif sub_hung:
                hung.append(start + i)
                decoded[start + i] = False
            else:
                decoded[start + i] = sub_dec.get(0, False)
        start += len(chunk)
    return decoded, crashed


def main(argv=None, *, harness: str | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="mac:<framework>")
    ap.add_argument("dir", type=pathlib.Path)
    ap.add_argument("--ok", type=pathlib.Path, default=None, help="copy decoded files here")
    ap.add_argument("--crashes", type=pathlib.Path, default=None,
                    help="copy crashing files here")
    ap.add_argument("--hangs", type=pathlib.Path, default=None,
                    help="copy files that hang here (liveness only, not candidates)")
    ap.add_argument("--timeout", type=float, default=PER_FILE_TIMEOUT_S,
                    help=f"seconds per input before it counts as a hang "
                         f"(default {PER_FILE_TIMEOUT_S}; raise it for large files)")
    args = ap.parse_args(argv)
    harness = harness or str(create(args.target).resolve_harness() or "")
    if not harness:
        print(f"error: harness for {args.target} is not built", file=sys.stderr)
        return 3
    files = sorted(p for p in args.dir.iterdir() if p.is_file())
    hung: list[int] = []
    decoded, crashed = run(harness, files, hung, args.timeout)
    total, good = Counter(), Counter()
    for i, f in enumerate(files):
        total[kind(f)] += 1
        good[kind(f)] += decoded.get(i, False)
    for k in sorted(total):
        print(f"{k:28s} {good[k]:6d}/{total[k]:<6d} {good[k] / total[k]:6.0%}")
    n_ok = sum(good.values())
    print(f"{'TOTAL':28s} {n_ok:6d}/{len(files):<6d} {n_ok / max(1, len(files)):6.0%}"
          f"   crashed: {len(crashed)}   hung: {len(hung)}")
    for dest, picks in ((args.ok, [f for i, f in enumerate(files) if decoded.get(i)]),
                        (args.crashes, [files[i] for i in crashed]),
                        (args.hangs, [files[i] for i in hung])):
        if dest and picks:
            dest.mkdir(parents=True, exist_ok=True)
            for f in picks:
                shutil.copy2(f, dest / f.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

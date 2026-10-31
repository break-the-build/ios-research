#!/usr/bin/env python3
"""Decode gate for generated seeds: how many decode, per variant kind.

Runs the standalone harness over a directory in batches and parses its DONE
lines. A file counts as decoded when the harness says ``decoded`` with a
non-zero depth metric (``pixels=`` / ``frames=``), or just ``decoded`` for
targets without one. Files that crash the harness are copied to
``--crashes`` (a crash at the gate is a candidate: triage it 3/3). Kinds come
from the generators' variant names (``Arial-hint-glyph12-7.ttf`` ->
``hint-glyph``, ``x-ifd1-jpegNf-4.dng`` -> ``ifd1-jpegNf``), so a generator
mode that rarely decodes stands out.

Authorized / own-machine research only (SECURITY.md).

Usage:
    python tools/gen/gate.py --target mac:coretext DIR [--ok OK_DIR] [--crashes DIR]
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


def run(harness: str, files: list[pathlib.Path]) -> tuple[dict[int, bool], list[int]]:
    """index -> decoded, plus the indexes that crashed (isolated one by one)."""
    decoded: dict[int, bool] = {}
    crashed: list[int] = []
    for start in range(0, len(files), BATCH):
        chunk = files[start:start + BATCH]
        try:
            proc = subprocess.run([harness, *map(str, chunk)], capture_output=True,
                                  check=False, env=os.environ.copy(),
                                  timeout=PER_FILE_TIMEOUT_S * len(chunk))
            ok = proc.returncode == 0
        except subprocess.TimeoutExpired:
            ok, proc = False, None
        if not ok:
            if len(chunk) == 1:
                crashed.append(start)
                continue
            for i in range(len(chunk)):
                sub_dec, sub_crash = run(harness, [chunk[i]])
                if sub_crash:
                    crashed.append(start + i)
                else:
                    decoded[start + i] = sub_dec.get(0, False)
            continue
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            st = _status(line)
            if st:
                decoded[start + st[0]] = st[1]
    return decoded, crashed


def main(argv=None, *, harness: str | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="mac:<framework>")
    ap.add_argument("dir", type=pathlib.Path)
    ap.add_argument("--ok", type=pathlib.Path, default=None, help="copy decoded files here")
    ap.add_argument("--crashes", type=pathlib.Path, default=None,
                    help="copy crashing files here")
    args = ap.parse_args(argv)
    harness = harness or str(create(args.target).resolve_harness() or "")
    if not harness:
        print(f"error: harness for {args.target} is not built", file=sys.stderr)
        return 3
    files = sorted(p for p in args.dir.iterdir() if p.is_file())
    decoded, crashed = run(harness, files)
    total, good = Counter(), Counter()
    for i, f in enumerate(files):
        total[kind(f)] += 1
        good[kind(f)] += decoded.get(i, False)
    for k in sorted(total):
        print(f"{k:28s} {good[k]:6d}/{total[k]:<6d} {good[k] / total[k]:6.0%}")
    n_ok = sum(good.values())
    print(f"{'TOTAL':28s} {n_ok:6d}/{len(files):<6d} {n_ok / max(1, len(files)):6.0%}"
          f"   crashed: {len(crashed)}")
    for dest, picks in ((args.ok, [f for i, f in enumerate(files) if decoded.get(i)]),
                        (args.crashes, [files[i] for i in crashed])):
        if dest and picks:
            dest.mkdir(parents=True, exist_ok=True)
            for f in picks:
                shutil.copy2(f, dest / f.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

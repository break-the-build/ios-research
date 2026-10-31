#!/usr/bin/env python3
"""Streaming, parallel field-mismatch sweep over real camera RAW files (lane 1).

``dng.py mismatch`` writes every variant to disk; a 30 MB RAW file with
``--all-tags`` makes thousands of full-size copies. This sweep writes a few
variants at a time, runs them through the standalone harness on several
workers (``gate.run``: batches, crashes isolated one by one), keeps only the
files that crashed or hung, and deletes the rest. The oracle is whatever the
environment says: the harness links Guard Malloc; export
``MALLOC_PROTECT_BEFORE=1`` for the underflow oracle.

A file listed under ``crashed`` is only a lead: replay it alone 3 times
before calling it a candidate. ``hung`` files are liveness, not findings.

Authorized / own-machine research only (SECURITY.md).

Usage:
    python tools/gen/rawsweep.py --target mac:imageio RAW ... --work DIR \\
        --crashes DIR [--all-tags] [--makernote N] [--workers 8] [--report JSON]
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import time
from collections import Counter, deque
from concurrent.futures import Future, ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import dng  # noqa: E402
import gate  # noqa: E402

CHUNK_BYTES = 128 << 20          # bytes of variants per chunk on disk


def classify(harness: str, path: pathlib.Path) -> str:
    """Re-run one file alone: 'crash' (killed by a signal), 'hang' or 'error'."""
    try:
        proc = subprocess.run([harness, str(path)], capture_output=True, check=False,
                              env=os.environ.copy(), timeout=gate.PER_FILE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return "hang"
    return "crash" if proc.returncode < 0 else "error"


def _run_chunk(harness: str, files: list[pathlib.Path]) -> tuple[list, list]:
    decoded, crashed = gate.run(harness, files)
    leads = [(files[i], classify(harness, files[i])) for i in crashed]
    return [decoded.get(i, False) for i in range(len(files))], leads


def sweep(harness: str, raws: list[pathlib.Path], work: pathlib.Path,
          crashes: pathlib.Path, *, workers: int = 8, **variant_kw) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    total, good = Counter(), Counter()
    leads: list[dict] = []
    pending: deque[tuple[Future, pathlib.Path, list[pathlib.Path]]] = deque()
    started, n_chunk = time.time(), 0

    def collect(entry) -> None:
        fut, chunk_dir, files = entry
        ok, chunk_leads = fut.result()
        for f, flag in zip(files, ok):
            good[gate.kind(f)] += flag
        for f, verdict in chunk_leads:
            dest = crashes / ("hung" if verdict == "hang" else "crashed")
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest / f.name)
            leads.append({"file": f.name, "verdict": verdict})
        shutil.rmtree(chunk_dir, ignore_errors=True)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for raw in raws:
            data = raw.read_bytes()
            per_chunk = max(1, min(gate.BATCH, CHUNK_BYTES // max(1, len(data))))
            suffix = raw.suffix.lower() or ".raw"
            try:
                variants = dng.mismatch_variants(data, **variant_kw)
                batch: list[pathlib.Path] = []
                for name, blob in variants:
                    if not batch:
                        n_chunk += 1
                        chunk_dir = work / f"chunk{n_chunk:06d}"
                        chunk_dir.mkdir()
                    path = chunk_dir / f"{raw.stem}-{name}{suffix}"
                    path.write_bytes(blob)
                    batch.append(path)
                    total[gate.kind(path)] += 1
                    if len(batch) == per_chunk:
                        pending.append((pool.submit(_run_chunk, harness, batch), chunk_dir, batch))
                        batch = []
                        while len(pending) >= 2 * workers:
                            collect(pending.popleft())
                if batch:
                    pending.append((pool.submit(_run_chunk, harness, batch), chunk_dir, batch))
            except (ValueError, struct.error, IndexError) as exc:
                print(f"skip {raw}: {exc}", file=sys.stderr)
            print(f"{raw.name}: {sum(total.values())} variants queued so far", file=sys.stderr)
        while pending:
            collect(pending.popleft())
    n = sum(total.values())
    return {"inputs": [str(r) for r in raws], "variants": n,
            "decoded": sum(good.values()), "elapsed_s": round(time.time() - started, 1),
            "kinds": {k: [good[k], total[k]] for k in sorted(total)},
            "leads": leads,
            "oracle": "before" if os.environ.get("MALLOC_PROTECT_BEFORE") == "1" else "default"}


def main(argv=None, *, harness: str | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="mac:imageio")
    ap.add_argument("raws", nargs="+", type=pathlib.Path)
    ap.add_argument("--work", type=pathlib.Path, required=True,
                    help="scratch dir for in-flight variants (emptied as it goes)")
    ap.add_argument("--crashes", type=pathlib.Path, required=True)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--report", type=pathlib.Path, default=None)
    dng.add_variant_args(ap)
    args = ap.parse_args(argv)
    harness = harness or str(gate.create(args.target).resolve_harness() or "")
    if not harness:
        print(f"error: harness for {args.target} is not built", file=sys.stderr)
        return 3
    result = sweep(harness, args.raws, args.work, args.crashes, workers=args.workers,
                   **dng.variant_kwargs(args))
    text = json.dumps(result, indent=2)
    if args.report:
        args.report.write_text(text)
    print(f"variants={result['variants']} decoded={result['decoded']} "
          f"leads={len(result['leads'])} elapsed={result['elapsed_s']}s "
          f"oracle={result['oracle']}")
    for lead in result["leads"]:
        print(f"LEAD {lead['verdict']} {lead['file']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run a real macOS in-process fuzzing campaign against a mac:<framework> target.

This is a *real-signal campaign* runner, deliberately separate from the
experiment-loop framework (which optimizes strategy knobs against deterministic
mock metrics — native crashes have no honest knob->metric gradient; see
docs/MAC-FUZZING.md). It seeds a corpus from the target's format-aware seeds,
mutates with the shared mutation engine, drives inputs through the target in
batches for throughput, and summarizes real ASan-backed crashes.

Authorized / own-machine research only (SECURITY.md).

Usage:
    # build the harness first (see docs/MAC-FUZZING.md):
    tools/harness/build.sh imageio

    python tools/mac_campaign/run.py --target mac:imageio --cases 2000
    python tools/mac_campaign/run.py --target mac:imageio --cases 2000 \\
        --report /tmp/campaign.json --save-crashes /tmp/crashes
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time

# Make the package importable when run from a checkout without installation.
_REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "src"))

from ios_research import mutation  # noqa: E402
from ios_research.targets import create  # noqa: E402
from ios_research.targets.base import Outcome  # noqa: E402


def _seed_corpus(target) -> list[bytes]:
    seeds = target.seeds()
    return seeds or [b"\x00" * 16]


def run_campaign(target_id: str, cases: int, seed: int, batch: int,
                 workers: int = 1):
    target = create(target_id)
    if not getattr(target, "available", lambda: True)():
        print(f"error: harness for {target_id} is not built/available.\n"
              f"       build it: tools/harness/build.sh "
              f"{target_id.split(':', 1)[-1]}\n"
              f"       or set $IOS_RESEARCH_MAC_HARNESS. See docs/MAC-FUZZING.md.",
              file=sys.stderr)
        return None

    corpus = _seed_corpus(target)
    counts: dict[str, int] = {o: 0 for o in Outcome.ALL}
    crashes: list[dict] = []
    crash_inputs: list[bytes] = []
    seen_sigs: set[str] = set()

    # Materialize the deterministic (seed, iteration) inputs, split into batches.
    batches: list[list[bytes]] = []
    for start_i in range(0, cases, batch):
        chunk = []
        for i in range(start_i, min(start_i + batch, cases)):
            base = corpus[i % len(corpus)]
            data, _strategy = mutation.mutate(base, seed, i)
            chunk.append(data)
        batches.append(chunk)

    # More workers than batches is pure overhead.
    workers = max(1, min(workers, len(batches)))

    start = time.monotonic()
    # execute_batch spawns a subprocess (releasing the GIL while it waits), so a
    # thread pool spreads batches across CPU cores. workers=1 => serial.
    if workers <= 1 or len(batches) <= 1:
        batch_results = [(b, target.execute_batch(b)) for b in batches]
    else:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results_map = list(pool.map(target.execute_batch, batches))
        batch_results = list(zip(batches, results_map))
    elapsed = time.monotonic() - start

    produced = 0
    for chunk_inputs, results in batch_results:
        for data, res in zip(chunk_inputs, results):
            produced += 1
            counts[res.outcome] = counts.get(res.outcome, 0) + 1
            if res.outcome == Outcome.CRASH and res.diagnostics is not None:
                sig = res.diagnostics.signature
                crashes.append({
                    "signature": sig,
                    "classification": res.diagnostics.classification_hint,
                    "faulting_address": res.diagnostics.faulting_address,
                    "detail": res.detail,
                    "top_frames": res.diagnostics.stack_trace[:5],
                    "unique": sig not in seen_sigs,
                })
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    crash_inputs.append(data)

    return {
        "target": target_id,
        "cases": produced,
        "seed": seed,
        "batch": batch,
        "workers": workers,
        "elapsed_s": round(elapsed, 2),
        "exec_per_s": round(produced / elapsed, 1) if elapsed else 0.0,
        "counts": counts,
        "total_crashes": len(crashes),
        "unique_crashes": len(seen_sigs),
        "crashes": crashes,
    }, crash_inputs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="mac:imageio",
                    help="mac:<framework> target id (default: mac:imageio)")
    ap.add_argument("--cases", type=int, default=1000, help="inputs to run")
    ap.add_argument("--seed", type=int, default=1337, help="RNG seed")
    ap.add_argument("--batch", type=int, default=256,
                    help="inputs per harness process (throughput; default 256)")
    ap.add_argument("--workers", type=int, default=0,
                    help="concurrent harness processes; 0 = auto (~half the CPUs)")
    ap.add_argument("--report", default=None, help="write JSON summary to this path")
    ap.add_argument("--save-crashes", default=None,
                    help="directory to write one input file per unique crash")
    args = ap.parse_args(argv)

    workers = args.workers
    if workers <= 0:
        # Throughput plateaus at ~4-6 concurrent ASan processes and regresses
        # beyond that (memory/scheduler contention), so cap the auto default.
        workers = max(1, min(6, (os.cpu_count() or 2) // 2))
    out = run_campaign(args.target, args.cases, args.seed, max(1, args.batch),
                       workers=workers)
    if out is None:
        return 3
    summary, crash_inputs = out

    if args.save_crashes and crash_inputs:
        d = pathlib.Path(args.save_crashes)
        d.mkdir(parents=True, exist_ok=True)
        for c, data in zip(summary["crashes"], crash_inputs):
            (d / f"crash_{c['signature']}.input").write_bytes(data)

    text = json.dumps(summary, indent=2)
    if args.report:
        pathlib.Path(args.report).write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

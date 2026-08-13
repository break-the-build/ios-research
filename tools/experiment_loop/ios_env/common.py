"""Shared helpers for the ios-research experiment-loop environments."""

from __future__ import annotations

import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

from ios_research import __version__, mutation, targets
from ios_research.clock import now_iso
from ios_research.targets.base import Outcome
from ios_research.workspace import Workspace

STRATEGIES = mutation.STRATEGIES

# Distinct crash classifications reachable in mock:parser — the coverage
# denominator for effectiveness metrics.
KNOWN_SIGNATURES = 6

# Classifications that represent memory-safety issues (spatial/temporal/type
# confusion) — the "actionable" findings for research-efficiency metrics.
MEMORY_SAFETY_CLASSES = frozenset({
    "OUT_OF_BOUNDS_READ", "OUT_OF_BOUNDS_WRITE", "USE_AFTER_FREE",
    "TYPE_CONFUSION",
})


def base_input(target_id: str) -> bytes:
    """A valid seed input accepted by ``target_id``."""
    target = targets.create(target_id)
    seeds = target.seeds()
    return seeds[0] if seeds else b"MOCK" + bytes([1, 1]) + (2).to_bytes(2, "big") + b"ok"


def weights_from_config(config: Mapping[str, Any]) -> dict[str, int]:
    """Extract ``weight_<strategy>`` knobs into a weight map (default 1)."""
    return {s: int(config.get(f"weight_{s}", 1)) for s in STRATEGIES}


def fuzz_once(target_id: str, weights: dict[str, int] | None, *, budget: int,
              seed: int) -> dict[str, Any]:
    """Run one fuzzing pass and collect crash evidence.

    Mirrors the FuzzEngine inner step (``mutation.mutate`` -> ``target.execute``)
    so measurements reflect real engine behavior.
    """
    target = targets.create(target_id)
    struct_fn = target.structure_mutate
    base = base_input(target_id)
    signatures: dict[str, bytes] = {}
    classifications: dict[str, str] = {}
    inputs: set[str] = set()
    crashes = 0
    for i in range(budget):
        data, _ = mutation.mutate(base, seed, i, struct_fn=struct_fn,
                                  weights=weights or None)
        inputs.add(data.hex())
        result = target.execute(data)
        if result.outcome in (Outcome.CRASH, Outcome.ABNORMAL) and result.diagnostics:
            crashes += 1
            sig = result.diagnostics.signature
            signatures.setdefault(sig, data)
            classifications.setdefault(sig, result.diagnostics.classification_hint)
    return {
        "signatures": signatures,          # sig -> first triggering input
        "classifications": classifications,  # sig -> crash classification
        "unique": len(signatures),
        "unique_inputs": len(inputs),
        "crashes": crashes,
        "executed": budget,
    }


@contextmanager
def temp_workspace():
    """Yield a throwaway initialized Workspace (auto-removed)."""
    with tempfile.TemporaryDirectory(prefix="ios-el-") as tmp:
        ws = Workspace(Path(tmp) / ".ios-research")
        ws.init(framework_version=__version__, created_at=now_iso())
        yield ws
